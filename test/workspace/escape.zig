//! Tests that try to escape the sandbox around a real workspace: a throwaway
//! git worktree, mounted the way `Workspace.sandboxConfig` builds it.
//! `Sandbox.spawn` needs a single threaded caller, so this starts `escape_probe` as a fresh process instead.

const std = @import("std");
const linux = std.os.linux;
const chock_workspace = @import("chock-workspace");
const sandbox = @import("chock-sandbox");
const Workspace = chock_workspace.Workspace;
const git = chock_workspace.git;

// The default test runner panics on any argv it does not recognize, so build.zig embeds the probe path.
const escape_probe_path = @import("escape_probe_path").escape_probe_path;

fn absoluteDirPath(buffer: []u8, dir_fd: linux.fd_t) ![:0]u8 {
    var link_buffer: [64]u8 = undefined;
    const link = std.fmt.bufPrintZ(&link_buffer, "/proc/self/fd/{d}", .{dir_fd}) catch unreachable;
    const rc = linux.readlink(link, buffer.ptr, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    const len: usize = @intCast(rc);
    buffer[len] = 0;
    return buffer[0..len :0];
}

fn testEnviron(allocator: std.mem.Allocator, scratch_path: []const u8) !std.process.Environ.Map {
    var env = try std.testing.environ.createMap(allocator);
    errdefer env.deinit();
    const ceiling = std.fs.path.dirname(scratch_path) orelse scratch_path;
    try env.put("GIT_CEILING_DIRECTORIES", ceiling);
    return env;
}

fn makeDir(path: [:0]const u8) !void {
    switch (linux.errno(linux.mkdirat(linux.AT.FDCWD, path.ptr, 0o755))) {
        .SUCCESS => {},
        else => return error.MkdirFailed,
    }
}

fn writeFile(io: std.Io, path: [:0]const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

const chock_zon_content =
    \\.{
    \\    .budget = .{ .max_cost = 5.0, .currency = "USD" },
    \\}
    \\
;

/// Never empty: a value that matched the deny notice would make a passing test say nothing.
const secret_content = "AWS_SECRET_ACCESS_KEY=this-must-never-reach-a-tool-call\n";

/// Two entries on purpose: one file the project holds, and one it does not.
const chock_zon_with_deny =
    \\.{
    \\    .budget = .{ .max_cost = 5.0, .currency = "USD" },
    \\    .deny_read = .{ "secret.env", ".env" },
    \\}
    \\
;

const TestProject = struct {
    allocator: std.mem.Allocator,
    root_path: [:0]const u8,
    scratch_path: [:0]const u8,
    env: std.process.Environ.Map,

    fn init(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) !TestProject {
        return initWith(allocator, tmp, chock_zon_content);
    }

    fn initWith(
        allocator: std.mem.Allocator,
        tmp: std.testing.TmpDir,
        chock_zon: []const u8,
    ) !TestProject {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_path = try absoluteDirPath(&buffer, tmp.dir.handle);

        var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const root_path = try std.fmt.bufPrintZ(&root_buffer, "{s}/project", .{tmp_path});
        try makeDir(root_path);

        var scratch_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const scratch_path = try std.fmt.bufPrintZ(&scratch_buffer, "{s}/scratch", .{tmp_path});
        try makeDir(scratch_path);

        var env = try testEnviron(allocator, tmp_path);
        errdefer env.deinit();

        var init_output = try git.run(allocator, std.testing.io, &env, root_path, &.{"init"}, null);
        defer init_output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, init_output.term);

        var config_email = try git.run(allocator, std.testing.io, &env, root_path, &.{ "config", "user.email", "test@example.com" }, null);
        defer config_email.deinit(allocator);
        var config_name = try git.run(allocator, std.testing.io, &env, root_path, &.{ "config", "user.name", "Test" }, null);
        defer config_name.deinit(allocator);

        var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{root_path});
        try writeFile(std.testing.io, tracked_path, "hello\n");

        var secret_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const secret_path = try std.fmt.bufPrintZ(&secret_buffer, "{s}/secret.env", .{root_path});
        try writeFile(std.testing.io, secret_path, secret_content);

        var chock_zon_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const chock_zon_path = try std.fmt.bufPrintZ(&chock_zon_buffer, "{s}/chock.zon", .{root_path});
        try writeFile(std.testing.io, chock_zon_path, chock_zon);

        var add_output = try git.run(allocator, std.testing.io, &env, root_path, &.{ "add", "tracked.txt", "secret.env", "chock.zon" }, null);
        defer add_output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, add_output.term);

        var commit_output = try git.run(allocator, std.testing.io, &env, root_path, &.{ "commit", "-m", "first commit" }, null);
        defer commit_output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, commit_output.term);

        return .{
            .allocator = allocator,
            .root_path = try allocator.dupeZ(u8, root_path),
            .scratch_path = try allocator.dupeZ(u8, scratch_path),
            .env = env,
        };
    }

    fn deinit(self: *TestProject) void {
        self.allocator.free(self.root_path);
        self.allocator.free(self.scratch_path);
        self.env.deinit();
    }
};

/// `root_path` is never a git repository, so `Workspace.open` picks the overlay.
const PlainProject = struct {
    allocator: std.mem.Allocator,
    root_path: [:0]const u8,
    scratch_path: [:0]const u8,
    env: std.process.Environ.Map,

    fn init(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) !PlainProject {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_path = try absoluteDirPath(&buffer, tmp.dir.handle);

        var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const root_path = try std.fmt.bufPrintZ(&root_buffer, "{s}/project", .{tmp_path});
        try makeDir(root_path);

        var scratch_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const scratch_path = try std.fmt.bufPrintZ(&scratch_buffer, "{s}/scratch", .{tmp_path});
        try makeDir(scratch_path);

        const env = try testEnviron(allocator, tmp_path);

        return .{
            .allocator = allocator,
            .root_path = try allocator.dupeZ(u8, root_path),
            .scratch_path = try allocator.dupeZ(u8, scratch_path),
            .env = env,
        };
    }

    fn deinit(self: *PlainProject) void {
        self.allocator.free(self.root_path);
        self.allocator.free(self.scratch_path);
        self.env.deinit();
    }
};

/// One line per mount, fields separated by 0x01, the first field always the kind.
fn serializeMounts(allocator: std.mem.Allocator, mounts: []const sandbox.namespace.Mount) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (mounts) |m| {
        const line = switch (m) {
            .bind => |b| try std.fmt.allocPrint(
                allocator,
                "bind\x01{s}\x01{s}\x01{d}\n",
                .{ b.source, b.target, @intFromBool(b.read_only) },
            ),
            .overlay => |o| try std.fmt.allocPrint(
                allocator,
                "overlay\x01{s}\x01{s}\x01{s}\x01{s}\n",
                .{ o.lower, o.upper, o.work, o.target },
            ),
            .proc => |p| try std.fmt.allocPrint(
                allocator,
                "proc\x01{s}\n",
                .{p.target},
            ),
            .deny => |d| try std.fmt.allocPrint(
                allocator,
                "deny\x01{s}\n",
                .{d.target},
            ),
        };
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    return out.toOwnedSlice(allocator);
}

fn serializeRules(allocator: std.mem.Allocator, rules: []const sandbox.Config.Rule) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (rules) |r| {
        const line = try std.fmt.allocPrint(allocator, "{s}\x01{d}\n", .{ r.path, r.access.bits() });
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    return out.toOwnedSlice(allocator);
}

fn serializeEnv(allocator: std.mem.Allocator, env: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (env) |entry| {
        try out.appendSlice(allocator, entry);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

/// `root_tmp` is the sandbox root, kept apart from the project and scratch directories.
fn runProbe(
    allocator: std.mem.Allocator,
    workspace: *const Workspace,
    root_tmp: std.testing.TmpDir,
    op: []const u8,
    target: []const u8,
) !std.process.Child.Term {
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try absoluteDirPath(&root_buffer, root_tmp.dir.handle);

    const config = try workspace.sandboxConfig(allocator, root_path);
    defer allocator.free(config.mounts);
    defer allocator.free(config.rules);
    defer allocator.free(config.env);

    const mounts_blob = try serializeMounts(allocator, config.mounts);
    defer allocator.free(mounts_blob);
    const rules_blob = try serializeRules(allocator, config.rules);
    defer allocator.free(rules_blob);
    const env_blob = try serializeEnv(allocator, config.env);
    defer allocator.free(env_blob);

    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ escape_probe_path, op, root_path, config.cwd, mounts_blob, rules_blob, env_blob, target },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(term);
    return term;
}

/// Skip when the probe answered that this machine would not give it a sandbox.
fn skipIfNothingMeasured(term: std.process.Child.Term) !void {
    const code = switch (term) {
        .exited => |c| c,
        else => return,
    };
    if (code == sandbox.namespace.nothing_measured_exit_status) return error.SkipZigTest;
}

fn findGitOnPath(allocator: std.mem.Allocator, io: std.Io) !?[]u8 {
    const path_env = std.process.Environ.getPosix(std.testing.environ, "PATH") orelse return null;
    var it = std.mem.tokenizeScalar(u8, path_env, ':');
    while (it.next()) |dir| {
        const candidate = try std.fs.path.join(allocator, &.{ dir, "git" });
        if (std.Io.Dir.cwd().statFile(io, candidate, .{})) |_| {
            return candidate;
        } else |_| {
            allocator.free(candidate);
        }
    }
    return null;
}

test "a tool call cannot write to .git/objects" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;
    const target = try std.fs.path.join(allocator, &.{ wt.sandbox_git_root, "objects", "chock-escape-probe" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "write", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a tool call cannot write to .git/hooks" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;
    const target = try std.fs.path.join(allocator, &.{ wt.sandbox_git_root, "hooks", "chock-escape-probe" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "write", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a tool call cannot delete chock.zon" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expect(workspace.chock_zon_source != null);

    const wt = workspace.kind.worktree;
    const target = try std.fs.path.join(allocator, &.{ wt.project_root, "chock.zon" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "delete", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a tool call cannot write to chock.zon" {
    // Unlinking a mount point answers EBUSY whether the mount is read only or not, so an open for write must fail too.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expect(workspace.chock_zon_source != null);

    const wt = workspace.kind.worktree;
    const target = try std.fs.path.join(allocator, &.{ wt.project_root, "chock.zon" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "write", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a read_only bind cannot be written to, and a write bind can" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    // Never committed, so only the bind puts them in front of the agent.
    var read_only_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const read_only_source = try std.fmt.bufPrintZ(&read_only_buffer, "{s}/generated.conf", .{project.root_path});
    try writeFile(std.testing.io, read_only_source, "a=1\n");

    var writable_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const writable_source = try std.fmt.bufPrintZ(&writable_buffer, "{s}/writable.conf", .{project.root_path});
    try writeFile(std.testing.io, writable_source, "b=1\n");

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const resolved = [_]chock_workspace.binds.Resolved{
        .{
            .name = "generated.conf",
            .relative = "generated.conf",
            .host_path = read_only_source,
            .mode = .read_only,
            .is_directory = false,
        },
        .{
            .name = "writable.conf",
            .relative = "writable.conf",
            .host_path = writable_source,
            .mode = .write,
            .is_directory = false,
            .read_only = false,
        },
    };

    var report = chock_workspace.worktree.ImportReport{};
    defer report.deinit(allocator);
    try workspace.attachBinds(allocator, std.testing.io, &resolved, true, &report);

    const refused = try std.fs.path.join(allocator, &.{ workspace.sandboxRoot(), "generated.conf" });
    defer allocator.free(refused);
    const permitted = try std.fs.path.join(allocator, &.{ workspace.sandboxRoot(), "writable.conf" });
    defer allocator.free(permitted);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 1 },
        try runProbe(allocator, &workspace, root_tmp, "write", refused),
    );
    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 0 },
        try runProbe(allocator, &workspace, root_tmp, "write", permitted),
    );
}

test "the agent cannot raise its own budget, because the budget lives in chock.zon" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expect(workspace.chock_zon_source != null);

    const wt = workspace.kind.worktree;
    const target = try std.fs.path.join(allocator, &.{ wt.project_root, "chock.zon" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "write", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);

    const after = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, target, allocator, .limited(4096));
    defer allocator.free(after);
    try std.testing.expectEqualStrings(chock_zon_content, after);
    try std.testing.expect(std.mem.indexOf(u8, after, ".max_cost = 5.0") != null);
}

test "a tool call can write in the worktree, so the sandbox is not a deny all" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;
    const target = try std.fs.path.join(allocator, &.{ wt.project_root, "chock-escape-write-test.txt" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "write", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a tool call can run git status inside the worktree, and the index is genuinely written to" {
    // `git status` exits zero whether the index write succeeded or not, so this reads the index bytes before and after instead.
    const allocator = std.testing.allocator;

    const git_path = (try findGitOnPath(allocator, std.testing.io)) orelse {
        return error.SkipZigTest;
    };
    defer allocator.free(git_path);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;

    // The index git writes is the session's own copy's, never the project's.
    var copy_index_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const copy_index_path = try std.fmt.bufPrint(&copy_index_buffer, "{s}/index", .{wt.worktree_meta_bind_source});

    const index_before = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, copy_index_path, allocator, .limited(1 << 20));
    defer allocator.free(index_before);

    const project_index_before = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_index_source, allocator, .limited(1 << 20));
    defer allocator.free(project_index_before);

    // Past git's one second mtime granularity, so the rewrite below is not read as racily clean.
    _ = linux.nanosleep(&.{ .sec = 1, .nsec = 100_000_000 }, null);

    // Same content, so only the mtime changes.
    var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{wt.path});
    try writeFile(std.testing.io, tracked_path, "hello\n");

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "git-status", git_path);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    const index_after = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, copy_index_path, allocator, .limited(1 << 20));
    defer allocator.free(index_after);
    try std.testing.expect(!std.mem.eql(u8, index_before, index_after));

    const project_index_after = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_index_source, allocator, .limited(1 << 20));
    defer allocator.free(project_index_after);
    try std.testing.expectEqualSlices(u8, project_index_before, project_index_after);
}

test "finding 4: a tool call writes the worktree metadata directory and the user's own repository never sees it" {
    // `.git/worktrees/<id>` is read write on purpose: `git add` and `git commit` rename lock files over it.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const probes = [_][]const u8{
        "logs/probe-from-session",
        "refs/probe-from-session",
        "probe-from-session",
    };

    for (probes) |relative| {
        var in_sandbox_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const in_sandbox = try std.fmt.bufPrint(&in_sandbox_buffer, "{s}/{s}", .{ wt.worktree_meta_target, relative });

        try std.testing.expectEqual(
            std.process.Child.Term{ .exited = 0 },
            try runProbe(allocator, &workspace, root_tmp, "write", in_sandbox),
        );

        var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const in_project = try std.fmt.bufPrint(&project_buffer, "{s}/{s}", .{ wt.worktree_meta_source, relative });
        try std.testing.expectError(
            error.FileNotFound,
            std.Io.Dir.cwd().statFile(std.testing.io, in_project, .{}),
        );

        var copy_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const in_copy = try std.fmt.bufPrint(&copy_buffer, "{s}/{s}", .{ wt.worktree_meta_bind_source, relative });
        _ = try std.Io.Dir.cwd().statFile(std.testing.io, in_copy, .{});
    }
}

test "finding 4: git status, git add, and git commit still work inside the sandbox" {
    const allocator = std.testing.allocator;

    const git_path = (try findGitOnPath(allocator, std.testing.io)) orelse return error.SkipZigTest;
    defer allocator.free(git_path);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;

    const project_head_before = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_head_source, allocator, .limited(1 << 16));
    defer allocator.free(project_head_before);

    var agent_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const agent_path = try std.fmt.bufPrintZ(&agent_buffer, "{s}/chock-object-store-test.txt", .{wt.path});
    try writeFile(std.testing.io, agent_path, "the agent wrote this inside the sandbox\n");

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 0 },
        try runProbe(allocator, &workspace, root_tmp, "git-commit", git_path),
    );

    const moved = (try wt.headMoved(allocator, std.testing.io, &project.env, null)) orelse
        return error.TheSessionsOwnCommitWasNotVisible;
    defer allocator.free(moved);
    try std.testing.expect(!std.mem.eql(u8, moved, wt.base_commit));

    const project_head_after = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_head_source, allocator, .limited(1 << 16));
    defer allocator.free(project_head_after);
    try std.testing.expectEqualSlices(u8, project_head_before, project_head_after);
}

/// The sandbox has no `HOME` to find `~/.gitconfig`, so this undoes the identity `TestProject.init` had to set for its first commit.
fn removeProjectIdentity(
    allocator: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    root_path: []const u8,
) !void {
    for ([_][]const u8{ "user.email", "user.name" }) |name| {
        var output = try git.run(allocator, std.testing.io, env, root_path, &.{ "config", "--unset", name }, null);
        defer output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    }

    var read_back = try git.run(allocator, std.testing.io, env, root_path, &.{ "config", "user.name" }, null);
    defer read_back.deinit(allocator);
    const still_set = switch (read_back.term) {
        .exited => |code| code == 0,
        else => true,
    };
    if (still_set) return error.TheProjectStillStatesAnIdentity;
}

test "a bare git commit inside the sandbox succeeds on a project that states no identity, and the commit is Chock's own" {
    // `git config` cannot make an identity because the whole of `.git` is mounted read only. No `-c` flag anywhere here.
    const allocator = std.testing.allocator;

    const git_path = (try findGitOnPath(allocator, std.testing.io)) orelse return error.SkipZigTest;
    defer allocator.free(git_path);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try removeProjectIdentity(allocator, &project.env, project.root_path);

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;

    var agent_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const agent_path = try std.fmt.bufPrintZ(&agent_buffer, "{s}/chock-object-store-test.txt", .{wt.path});
    try writeFile(std.testing.io, agent_path, "the agent wrote this inside the sandbox\n");

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 0 },
        try runProbe(allocator, &workspace, root_tmp, "git-commit", git_path),
    );

    const moved = (try wt.headMoved(allocator, std.testing.io, &project.env, null)) orelse
        return error.TheSessionsOwnCommitWasNotVisible;
    defer allocator.free(moved);

    // The commit object is in the session's own scratch store, so it comes in as an alternate for this read.
    var reading = try project.env.clone(allocator);
    defer reading.deinit();
    try reading.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", wt.object_store_source);
    var shown = try git.run(allocator, std.testing.io, &reading, project.root_path, &.{
        "show", "-s", "--format=%an%n%ae%n%cn%n%ce", moved,
    }, null);
    defer shown.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, shown.term);

    // Both: git takes author and committer from separate variables.
    try std.testing.expectEqualStrings(
        "Chock\nchock@lilithsemi.com\nChock\nchock@lilithsemi.com",
        std.mem.trimEnd(u8, shown.stdout, "\n"),
    );
}

test "the sandbox identity reaches no commit the user makes on the host" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;
    const config = try workspace.sandboxConfig(allocator, "/does-not-need-to-exist-for-this-check");
    defer allocator.free(config.mounts);
    defer allocator.free(config.rules);
    defer allocator.free(config.env);

    var host_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const host_path = try std.fmt.bufPrintZ(&host_buffer, "{s}/the-user-wrote-this.txt", .{project.root_path});
    try writeFile(std.testing.io, host_path, "mine\n");
    for ([_][]const []const u8{
        &.{ "add", "the-user-wrote-this.txt" },
        &.{ "commit", "-m", "the user's own commit" },
    }) |argv| {
        var output = try git.run(allocator, std.testing.io, &project.env, project.root_path, argv, null);
        defer output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    }

    var shown = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "show", "-s", "--format=%an%n%ae%n%cn%n%ce", "HEAD",
    }, null);
    defer shown.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, shown.term);
    try std.testing.expectEqualStrings(
        "Test\ntest@example.com\nTest\ntest@example.com",
        std.mem.trimEnd(u8, shown.stdout, "\n"),
    );
}

test "the config.worktree redirect stays closed even when a project has extensions.worktreeConfig on but no config.worktree of its own yet" {
    // core.fsmonitor or core.hooksPath written to config.worktree is host code execution on the next git status.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    // Never set a value with --worktree, or the main checkout's own .git/config.worktree is written instead.
    var config_output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "config", "extensions.worktreeConfig", "true",
    }, null);
    defer config_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, config_output.term);

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;
    try std.testing.expect(wt.worktree_config_worktree_is_scratch);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "write", wt.worktree_config_worktree_target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);

    var status_output = try git.run(allocator, std.testing.io, &project.env, wt.path, &.{"status"}, null);
    defer status_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, status_output.term);

    const contents = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_config_worktree_source, allocator, .limited(4096));
    defer allocator.free(contents);
    try std.testing.expectEqual(@as(usize, 0), contents.len);
}

fn countRealObjects(allocator: std.mem.Allocator, env: *const std.process.Environ.Map, root_path: []const u8) !usize {
    var output = try git.run(allocator, std.testing.io, env, root_path, &.{ "count-objects", "-v" }, null);
    defer output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);

    var total: usize = 0;
    var lines = std.mem.splitScalar(u8, output.stdout, '\n');
    while (lines.next()) |line| {
        inline for (.{ "count: ", "in-pack: " }) |prefix| {
            if (std.mem.startsWith(u8, line, prefix)) {
                total += try std.fmt.parseInt(usize, line[prefix.len..], 10);
            }
        }
    }
    return total;
}

fn captureRefs(allocator: std.mem.Allocator, env: *const std.process.Environ.Map, root_path: []const u8) ![]u8 {
    var output = try git.run(allocator, std.testing.io, env, root_path, &.{"show-ref"}, null);
    defer output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    return allocator.dupe(u8, output.stdout);
}

fn countRegularFiles(allocator: std.mem.Allocator, root_path: []const u8) !usize {
    var dir = try std.Io.Dir.openDirAbsolute(std.testing.io, root_path, .{ .iterate = true });
    defer dir.close(std.testing.io);

    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var count: usize = 0;
    while (try walker.next(std.testing.io)) |entry| {
        if (entry.kind == .file) count += 1;
    }
    return count;
}

test "git add and git commit succeed inside the sandbox, and the object lands only in the scratch store" {
    const allocator = std.testing.allocator;

    const git_path = (try findGitOnPath(allocator, std.testing.io)) orelse {
        return error.SkipZigTest;
    };
    defer allocator.free(git_path);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const objects_before = try countRealObjects(allocator, &project.env, project.root_path);
    const refs_before = try captureRefs(allocator, &project.env, project.root_path);
    defer allocator.free(refs_before);

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;

    // Never committed before, so git cannot skip writing the object.
    var new_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const new_file_path = try std.fmt.bufPrintZ(&new_file_buffer, "{s}/chock-object-store-test.txt", .{wt.path});
    try writeFile(std.testing.io, new_file_path, "chock overlay tamper\n");

    const scratch_files_before = try countRegularFiles(allocator, wt.object_store_source);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "git-commit", git_path);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    const scratch_files_after = try countRegularFiles(allocator, wt.object_store_source);
    try std.testing.expect(scratch_files_after > scratch_files_before);

    // The worktree was created detached, so the commit only updated the
    // worktree's own HEAD file and never a ref under refs/heads.
    const objects_after = try countRealObjects(allocator, &project.env, project.root_path);
    try std.testing.expectEqual(objects_before, objects_after);
    const refs_after = try captureRefs(allocator, &project.env, project.root_path);
    defer allocator.free(refs_after);
    try std.testing.expectEqualStrings(refs_before, refs_after);
}

test "an agent that renames its own GIT_ALTERNATE_OBJECT_DIRECTORIES gains nothing: it can still commit, but can no longer read history it did not just write" {
    // git never writes to an alternate, only reads from one, so tampering only costs the agent history it did not write itself.
    const allocator = std.testing.allocator;

    const git_path = (try findGitOnPath(allocator, std.testing.io)) orelse {
        return error.SkipZigTest;
    };
    defer allocator.free(git_path);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const objects_before = try countRealObjects(allocator, &project.env, project.root_path);
    const refs_before = try captureRefs(allocator, &project.env, project.root_path);
    defer allocator.free(refs_before);

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;

    var new_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const new_file_path = try std.fmt.bufPrintZ(&new_file_buffer, "{s}/chock-object-store-test.txt", .{wt.path});
    try writeFile(std.testing.io, new_file_path, "chock overlay tamper, alternate\n");

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    // The op commits, then replaces the alternate with a bogus path and reads the parent commit, which must now fail.
    const term = try runProbe(allocator, &workspace, root_tmp, "git-alternate-tamper", git_path);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    const objects_after = try countRealObjects(allocator, &project.env, project.root_path);
    try std.testing.expectEqual(objects_before, objects_after);
    const refs_after = try captureRefs(allocator, &project.env, project.root_path);
    defer allocator.free(refs_after);
    try std.testing.expectEqualStrings(refs_before, refs_after);
}

/// overlayfs leaves the nested "work" directory it makes inside `ov.work` with
/// mode 0000, and `tmpDir.cleanup` cannot delete a directory it cannot read. Put
/// the permission back first. Best effort: the mount may never have happened.
fn allowScratchCleanup(allocator: std.mem.Allocator, ov: chock_workspace.overlay.Overlay) void {
    const kernel_work_dir = std.fs.path.join(allocator, &.{ ov.work, "work" }) catch return;
    defer allocator.free(kernel_work_dir);
    const path_z = allocator.dupeZ(u8, kernel_work_dir) catch return;
    defer allocator.free(path_z);
    _ = linux.chmod(path_z.ptr, 0o700);
}

test "a tool call in the worktree kind writes into the workspace, not the user's project" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;
    const target = try std.fs.path.join(allocator, &.{ wt.project_root, "chock-abstraction-proof.txt" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "write", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    const in_worktree = try std.fs.path.join(allocator, &.{ wt.path, "chock-abstraction-proof.txt" });
    defer allocator.free(in_worktree);
    _ = try std.Io.Dir.cwd().statFile(std.testing.io, in_worktree, .{});

    const in_project = try std.fs.path.join(allocator, &.{ project.root_path, "chock-abstraction-proof.txt" });
    defer allocator.free(in_project);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, in_project, .{}),
    );
}

test "a tool call in the overlay kind writes into the workspace, not the user's project" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try PlainProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;
    try std.testing.expect(workspace.kind == .overlay);

    const ov = workspace.kind.overlay;
    const target = try std.fs.path.join(allocator, &.{ ov.project, "chock-abstraction-proof.txt" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "write", target);
    // Before `tmp.cleanup`, and whether or not the probe succeeded.
    allowScratchCleanup(allocator, ov);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    const in_upper = try std.fs.path.join(allocator, &.{ ov.upper, "chock-abstraction-proof.txt" });
    defer allocator.free(in_upper);
    _ = try std.Io.Dir.cwd().statFile(std.testing.io, in_upper, .{});

    const in_project = try std.fs.path.join(allocator, &.{ project.root_path, "chock-abstraction-proof.txt" });
    defer allocator.free(in_project);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, in_project, .{}),
    );
}

test "a denied file cannot be read by a real tool call, and reads as the notice" {
    // `secret.env` is committed, so the mount is all that stands between a tool call and its bytes.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.initWith(allocator, tmp, chock_zon_with_deny);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const in_checkout = try std.fs.path.join(allocator, &.{ workspace.workPath(), "secret.env" });
    defer allocator.free(in_checkout);
    const on_disk = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, in_checkout, allocator, .limited(4096));
    defer allocator.free(on_disk);
    try std.testing.expectEqualStrings(secret_content, on_disk);

    const target = try std.fs.path.join(allocator, &.{ workspace.kind.worktree.project_root, "secret.env" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "read", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "the same sandbox reads an ordinary file normally, so the denial is not a deny all" {
    // A probe that always answered "not the notice" would pass the test above and break every session.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.initWith(allocator, tmp, chock_zon_with_deny);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const target = try std.fs.path.join(allocator, &.{ workspace.kind.worktree.project_root, "tracked.txt" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "read", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a denied path the project does not hold yet is covered, and cannot be created" {
    // `.env` is in no commit, so `applyDenyMounts` makes an empty file to bind over instead.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.initWith(allocator, tmp, chock_zon_with_deny);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const in_checkout = try std.fs.path.join(allocator, &.{ workspace.workPath(), ".env" });
    defer allocator.free(in_checkout);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, in_checkout, .{}),
    );

    const target = try std.fs.path.join(allocator, &.{ workspace.kind.worktree.project_root, ".env" });
    defer allocator.free(target);

    var read_root = std.testing.tmpDir(.{});
    defer read_root.cleanup();
    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 1 },
        try runProbe(allocator, &workspace, read_root, "read", target),
    );

    var write_root = std.testing.tmpDir(.{});
    defer write_root.cleanup();
    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 1 },
        try runProbe(allocator, &workspace, write_root, "write", target),
    );

    // The empty file `applyDenyMounts` made is still in the checkout after the sandbox is gone.
    const left_behind = try std.Io.Dir.cwd().statFile(std.testing.io, in_checkout, .{});
    try std.testing.expectEqual(@as(u64, 0), left_behind.size);
}

test "a denied file cannot be deleted, so an agent cannot uncover it" {
    // The path is itself a mount point, and unlinking one answers EBUSY.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.initWith(allocator, tmp, chock_zon_with_deny);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const target = try std.fs.path.join(allocator, &.{ workspace.kind.worktree.project_root, "secret.env" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "delete", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "the denial survives the agent replacing chock.zon inside its own workspace" {
    // The deny list is fixed when the workspace opens. Nothing re-reads it today.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.initWith(allocator, tmp, chock_zon_with_deny);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    var edited_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const edited = try std.fmt.bufPrintZ(&edited_buffer, "{s}/chock.zon", .{workspace.workPath()});
    try writeFile(std.testing.io, edited, chock_zon_content);
    const after = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, edited, allocator, .limited(4096));
    defer allocator.free(after);
    try std.testing.expectEqualStrings(chock_zon_content, after);

    const target = try std.fs.path.join(allocator, &.{ workspace.kind.worktree.project_root, "secret.env" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "read", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a project that denies nothing gets no deny mount and reads its files as before" {
    // With no `.deny` entry `applyDenyMounts` returns before it makes any file.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expectEqual(@as(usize, 0), workspace.deny_paths.len);

    const config = try workspace.sandboxConfig(allocator, "/does-not-need-to-exist-for-this-check");
    defer allocator.free(config.mounts);
    defer allocator.free(config.rules);
    defer allocator.free(config.env);
    for (config.mounts) |mount| {
        try std.testing.expect(mount != .deny);
    }

    const target = try std.fs.path.join(allocator, &.{ workspace.kind.worktree.project_root, "secret.env" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "read", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the overlay kind denies a file the same way the worktree kind does" {
    // The denial is the same pass either way, because it runs after every other mount.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try PlainProject.init(allocator, tmp);
    defer project.deinit();

    var secret_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const secret_path = try std.fmt.bufPrintZ(&secret_buffer, "{s}/secret.env", .{project.root_path});
    try writeFile(std.testing.io, secret_path, secret_content);

    var zon_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const zon_path = try std.fmt.bufPrintZ(&zon_buffer, "{s}/chock.zon", .{project.root_path});
    try writeFile(std.testing.io, zon_path, chock_zon_with_deny);

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;
    try std.testing.expect(workspace.kind == .overlay);

    const ov = workspace.kind.overlay;
    const target = try std.fs.path.join(allocator, &.{ ov.project, "secret.env" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "read", target);
    allowScratchCleanup(allocator, ov);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);

    // `applyDenyMounts` reads the kind with `statx` and never opens an existing target, or overlayfs would copy it up.
    const in_upper = try std.fs.path.join(allocator, &.{ ov.upper, "secret.env" });
    defer allocator.free(in_upper);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, in_upper, .{}),
    );
}

test "a deny_read entry that names a directory refuses the whole session, by name" {
    // This design covers files and not directories.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.initWith(allocator, tmp,
        \\.{ .deny_read = .{ "credentials" } }
    );
    defer project.deinit();

    var credentials_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const credentials = try std.fmt.bufPrintZ(&credentials_buffer, "{s}/credentials", .{project.root_path});
    try makeDir(credentials);

    try std.testing.expectError(error.DenyPathIsDirectory, Workspace.open(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        null,
    ));
}

test "adopt takes the deny list from the project, not from the checkout it inherits" {
    // The `chock.zon` in an adopted checkout is whatever the last session left, so a handover must not read the deny list from there.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.initWith(allocator, tmp, chock_zon_with_deny);
    defer project.deinit();

    var head_output = try git.run(allocator, io, &project.env, project.root_path, &.{ "rev-parse", "HEAD" }, null);
    defer head_output.deinit(allocator);
    const base_commit = std.mem.trimEnd(u8, head_output.stdout, "\n");

    {
        var first = try Workspace.open(allocator, io, &project.env, project.root_path, project.scratch_path, "sess1", null);
        defer first.keep(allocator);

        var edited_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const edited = try std.fmt.bufPrintZ(&edited_buffer, "{s}/chock.zon", .{first.workPath()});
        try writeFile(io, edited, chock_zon_content);
    }

    var second = try Workspace.adopt(
        allocator,
        io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        base_commit,
        null,
    );
    defer second.close(allocator, io, &project.env, null) catch unreachable;

    const target = try std.fs.path.join(allocator, &.{ second.kind.worktree.project_root, "secret.env" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &second, root_tmp, "read", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}
