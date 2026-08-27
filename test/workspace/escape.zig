//! Tests that try to escape the sandbox around a real workspace: a throwaway
//! git worktree, mounted the way `Workspace.sandboxConfig` builds it. Each one
//! must fail to escape, except the two that prove the sandbox is not a deny
//! all. These three refusals could not be proved until the workspace
//! existed, because a sandbox on its own has no `.git` to protect.
//!
//! Every test here builds its own project inside a fresh `std.testing.tmpDir`
//! and sets its own `GIT_CEILING_DIRECTORIES`, the same pattern
//! `worktree.zig`'s own tests use and explain in full: this project's own
//! checkout is itself a git repository, and `tmpDir` makes every scratch
//! directory somewhere underneath it, so git's own upward search for a
//! `.git` directory would otherwise walk past a fresh scratch repository and
//! find this project's real one instead.
//!
//! A real `Sandbox.spawn` call needs a single threaded caller, the same
//! requirement `chock-sandbox`'s own escape tests and `chock-workspace`'s own
//! overlay tests already carry: see `test/workspace/escape_probe.zig`'s own
//! top comment. This test binary never calls `Sandbox.spawn` itself. It
//! starts `escape_probe` as a fresh process for that and reads its exit
//! status, the same pattern `test/sandbox/escape.zig` uses to run
//! `test/sandbox/probe.zig`.

const std = @import("std");
const linux = std.os.linux;
const chock_workspace = @import("chock-workspace");
const sandbox = @import("chock-sandbox");
const Workspace = chock_workspace.Workspace;
const git = chock_workspace.git;

// Zig 0.16 removed std.process.argsWithAllocator, and the default test
// runner panics on any argv it does not recognize, so the probe's path
// cannot come in as a CLI argument. build.zig embeds it as a build time
// constant instead, the same way it does for test/sandbox/probe.zig.
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

/// A fresh repository at `root_path`, one commit deep, with `tracked.txt` and
/// `chock.zon` both committed. The same shape as `worktree.zig`'s own
/// `TestProject`, with `chock.zon` added: the "cannot delete chock.zon" test
/// needs one committed, or a worktree checked out at HEAD would never have
/// it at all.
/// The `chock.zon` every project in this file is built with. It names a
/// budget, so "the agent cannot raise its own budget" is a fact about a cap
/// that is really written down: see `lib/chock-cost/budget.zig`.
const chock_zon_content =
    \\.{
    \\    .budget = .{ .max_cost = 5.0, .currency = "USD" },
    \\}
    \\
;

/// What `secret.env` holds in a project built with `TestProject.initWith`.
/// **Never the empty string, and never a repeat of another file's content**:
/// the deny tests read this path from inside a real sandbox and compare what
/// came back, so a value that happened to match the notice, or that read the
/// same as an empty file, would make a passing test say nothing.
const secret_content = "AWS_SECRET_ACCESS_KEY=this-must-never-reach-a-tool-call\n";

/// A `chock.zon` that denies `secret.env` and `.env`, beside the budget block
/// every project in this file already has. Two entries on purpose: one file
/// the project really holds, and one it does not hold at all.
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

    /// `init`, with the `chock.zon` named rather than assumed, and with a
    /// `secret.env` committed beside `tracked.txt`. The deny tests need a real
    /// file with real content in the project: a `deny_read` block pointed at
    /// nothing would pass every check below for the wrong reason.
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
        // A real budget block, not an empty file: the session's spending cap
        // lives in this file precisely because the deny_read block already
        // keeps the agent out of it, and the tests below prove that property
        // with the cap actually written down rather than taking it on trust
        // from an unrelated empty file.
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

/// A fresh project and scratch directory pair, both directly under the same
/// `tmpDir`, kept apart the same way `TestProject` keeps them apart. Unlike
/// `TestProject`, `root_path` is never turned into a git repository, so
/// `Workspace.open` picks the overlay kind for it. Used by the test that
/// drives both workspace kinds through `runProbe`, to prove neither the
/// caller nor `runProbe` itself has to know which kind it got.
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

/// Serialize `mounts` the way `escape_probe.zig`'s own top comment documents:
/// one line per mount, fields separated by 0x01, the first field always the
/// kind ("bind", "overlay", "proc" or "deny") so `escape_probe.zig` can parse
/// any of them back into a real `sandbox.namespace.Mount`. The caller owns the
/// returned slice.
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

/// Same shape as `serializeMounts`, for a rules list.
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

/// Serialize `env`, the environment `Workspace.sandboxConfig` built (the
/// `GIT_OBJECT_DIRECTORY` and `GIT_ALTERNATE_OBJECT_DIRECTORIES` for the
/// worktree kind, empty for the overlay kind), one "KEY=VALUE" line per
/// entry. Each entry is already a complete "KEY=VALUE" string, so this needs
/// no field separator the way `serializeMounts` and `serializeRules` do. The
/// caller owns the returned slice.
fn serializeEnv(allocator: std.mem.Allocator, env: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (env) |entry| {
        try out.appendSlice(allocator, entry);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

/// Run `escape_probe` with `op` and `target`, against a sandbox built from
/// `workspace`'s own `Sandbox.Config`, inside a fresh scratch root.
/// `root_tmp` is a caller-owned `std.testing.tmpDir`, the sandbox's own root:
/// kept separate from the project and scratch directories `TestProject` and
/// `Workspace.open` already used, the same way `test/sandbox/escape.zig`'s
/// own `scratchRoot` keeps a probe's sandbox root apart from everything the
/// test building it already made.
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

    // The probe reports through its exit status, which is the only thing a
    // caller here reads. Its standard error goes nowhere on purpose: see the
    // same spawn in `test/broker/support.zig` for the whole reason.
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

/// Skip when the probe answered "this machine would not give me a sandbox".
///
/// **A boundary that was never reached is not a boundary that held.** Every
/// test here asks whether a workspace mount stops something, and every one
/// needs a real sandbox to ask inside, so a machine that refuses one measures
/// nothing and must not report a row of passes. A skip is what says so. See
/// `namespace.nothing_measured_exit_status`, and the CI job named "Sandbox",
/// which runs this suite on a machine that can host one and fails rather than
/// skips.
fn skipIfNothingMeasured(term: std.process.Child.Term) !void {
    const code = switch (term) {
        .exited => |c| c,
        else => return,
    };
    if (code == sandbox.namespace.nothing_measured_exit_status) return error.SkipZigTest;
}

/// Find `git` on this process's own PATH, the same binary `nix develop`
/// already put there for every other git call in this project. Returns null
/// when it cannot be found, so the one test that needs a real git binary can
/// skip cleanly instead of failing for an environment reason unrelated to
/// the sandbox itself.
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

    // chock.zon was committed, so Workspace.open must have found it in the
    // worktree's own checkout and set up its protection: without that, this
    // test would pass for the wrong reason, a target path that simply is
    // not mounted at all rather than one that is mounted read only.
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
    // Finding 3: the test above only proves chock.zon cannot be unlinked,
    // and that stays true whether the mount is read only or not, because
    // unlinking a mount point is EBUSY either way, from the kernel, not
    // from Landlock or a read only bind. A reviewer who flipped the mount
    // to read write left the delete test green. This test pins the other
    // half: an open for write must fail too, with the EROFS a read only
    // bind mount gives, which a writable mount would not.
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

test "the agent cannot raise its own budget, because the budget lives in chock.zon" {
    // The cap is a control the user holds and the model cannot touch, and
    // that property comes for free from the read only bind of the project's
    // own `chock.zon`. "For free" is worth
    // proving rather than asserting: this writes a real budget block, has a
    // sandboxed tool call try to write over it, and then reads the file back
    // to show the number the session is capped at did not move.
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

    // The bytes the cap is read from, unchanged. A write that had gone
    // through would have replaced this content, and a session started
    // afterwards would have run under whatever the model wrote.
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
    // The index has to be writable for this. It is the test that catches a
    // mount list which is too strict, and the tests above catch one that is
    // too loose: a linked worktree writes its own .git/worktrees/<id>/index
    // on an ordinary status, and if that mount were read only, git would
    // fail on the lock file and every tool call that touches git would
    // break with it.
    //
    // Finding 2: a worktree fresh out of `create` has an index that already
    // matches what git checked out, so a plain `git status` right after
    // needs no refresh write at all, and this test used to pass even with
    // the whole metadata directory mounted read only, appended last in the
    // list so the kernel took it: nothing here ever exercised index
    // writability, the one thing this test exists to pin. Confirmed by hand
    // that a plain `git status` never fails on exit code either way, read
    // only index or not, because git treats the refresh write as a silent,
    // best effort optimization: mounting the whole metadata directory read
    // only in the same way, by hand, left this test green even then. So
    // this test does not trust the exit code alone. It touches a tracked
    // file's mtime, without changing its content, which is exactly the
    // shape a plain `git status` will safely refresh the cached stat entry
    // for, then reads the index bytes on the host before and after the
    // probe runs and requires them to differ: a read only mount leaves the
    // index untouched, and only a genuinely writable one lets git rewrite
    // it.
    const allocator = std.testing.allocator;

    const git_path = (try findGitOnPath(allocator, std.testing.io)) orelse {
        // A skip needs no message: a test that writes to standard error and
        // passes still puts a `failed command:` line in the build log.
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

    // **The index git writes is the session's own copy's**, never the
    // project's: `Worktree.mounts`'s own entry 3 binds the copy, so this
    // reads there. The project's own index is read too, and required to be
    // untouched afterwards, which is finding 4's own property.
    var copy_index_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const copy_index_path = try std.fmt.bufPrint(&copy_index_buffer, "{s}/index", .{wt.worktree_meta_bind_source});

    const index_before = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, copy_index_path, allocator, .limited(1 << 20));
    defer allocator.free(index_before);

    const project_index_before = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_index_source, allocator, .limited(1 << 20));
    defer allocator.free(project_index_before);

    // A gap short enough to make tracked.txt's new mtime land in the same
    // second as the index's own cached entry for it makes git treat the
    // file as "racily clean" and refuse to trust a stat only refresh for
    // it, confirmed by hand: this test would then see the index rewritten
    // for the wrong reason (a full re-hash every time, mount read only or
    // not) rather than the one Finding 2 exists to pin. 1.1 seconds is
    // comfortably past git's one second timestamp granularity.
    _ = linux.nanosleep(&.{ .sec = 1, .nsec = 100_000_000 }, null);

    // Same content as TestProject.init already wrote and committed: only
    // the mtime changes, so git's own safe refresh path applies, not a real
    // "modified" report that a plain git status would never write back on
    // its own.
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

    // And the project's own index did not move one byte while that happened,
    // which is what makes the line above a write to the copy rather than a
    // write to the user's repository.
    const project_index_after = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_index_source, allocator, .limited(1 << 20));
    defer allocator.free(project_index_after);
    try std.testing.expectEqualSlices(u8, project_index_before, project_index_after);
}

test "finding 4: a tool call writes the worktree metadata directory and the user's own repository never sees it" {
    // **Finding 4, reproduced and then refused.** The first complete red team
    // run drove a tool call to write
    // `.git/worktrees/<id>/logs/probe-from-session` into the user's own
    // repository, and the 6 bytes were still on disk when the session ended.
    // `.git/worktrees/<id>` is read write on purpose: `git add` and
    // `git commit` create `index.lock` and `HEAD.lock` in it and rename each
    // over the file it locks, and a read only mount there answers `EROFS` on
    // the first `git add`. So the fix is not a read only mount but a
    // different directory: `Worktree.mounts` binds the session's own copy.
    //
    // This test drives the same three writes the red team session made, at
    // the same three paths, and requires each one to succeed inside the
    // sandbox, because a refusal is a broken workspace and not a fix. Then it
    // reads the project's own `.git/worktrees/<id>` on the host and requires
    // every one of the three to be absent there, and the copy to hold them.
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

    // The red team session's own three paths: the reflog directory, which is
    // the one the oracle caught, the per worktree refs directory, which it
    // did not catch because it accepts every name under `refs/`, and the root
    // of the directory itself, which no read only mount can ever cover.
    const probes = [_][]const u8{
        "logs/probe-from-session",
        "refs/probe-from-session",
        "probe-from-session",
    };

    for (probes) |relative| {
        var in_sandbox_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const in_sandbox = try std.fmt.bufPrint(&in_sandbox_buffer, "{s}/{s}", .{ wt.worktree_meta_target, relative });

        // Exit 0 is the write succeeding. A refusal here would mean the
        // metadata directory had stopped being writable, which is the state
        // that breaks every git command a tool call makes.
        try std.testing.expectEqual(
            std.process.Child.Term{ .exited = 0 },
            try runProbe(allocator, &workspace, root_tmp, "write", in_sandbox),
        );

        // The user's own repository never saw it, which is the whole
        // finding. Read first, so a build that put the file back in the
        // project fails on this line and names the fault, rather than
        // failing on the copy being empty and naming a symptom.
        var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const in_project = try std.fmt.bufPrint(&project_buffer, "{s}/{s}", .{ wt.worktree_meta_source, relative });
        try std.testing.expectError(
            error.FileNotFound,
            std.Io.Dir.cwd().statFile(std.testing.io, in_project, .{}),
        );

        // And it really was written, in the session's own copy: without this
        // the line above would hold just as well for a sandbox that refused
        // the write, which is a broken workspace and not a fix.
        var copy_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const in_copy = try std.fmt.bufPrint(&copy_buffer, "{s}/{s}", .{ wt.worktree_meta_bind_source, relative });
        _ = try std.Io.Dir.cwd().statFile(std.testing.io, in_copy, .{});
    }
}

test "finding 4: git status, git add, and git commit still work inside the sandbox" {
    // The other half of finding 4. A workspace that refuses the three writes
    // above and also refuses `git commit` has closed nothing worth having,
    // so this drives a real add and a real commit through a real sandbox,
    // against the copy, and then reads the commit back the way
    // `Worktree.headAfterSession` does.
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

    // What the metadata directory the project owns held before the session,
    // to compare against after it.
    const project_head_before = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_head_source, allocator, .limited(1 << 16));
    defer allocator.free(project_head_before);

    // The file the git-commit flow adds and commits, written on the host
    // into the checkout, with content nothing has committed before.
    var agent_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const agent_path = try std.fmt.bufPrintZ(&agent_buffer, "{s}/chock-object-store-test.txt", .{wt.path});
    try writeFile(std.testing.io, agent_path, "the agent wrote this inside the sandbox\n");

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    // The probe's own git-commit flow: git status, then git add, then git
    // commit, each one a separate sandbox of its own.
    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 0 },
        try runProbe(allocator, &workspace, root_tmp, "git-commit", git_path),
    );

    // The session's own commit is readable, and it is not the base.
    const moved = (try wt.headMoved(allocator, std.testing.io, &project.env, null)) orelse
        return error.TheSessionsOwnCommitWasNotVisible;
    defer allocator.free(moved);
    try std.testing.expect(!std.mem.eql(u8, moved, wt.base_commit));

    // And the project's own HEAD for this worktree never moved, because the
    // commit was written to the copy.
    const project_head_after = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_head_source, allocator, .limited(1 << 16));
    defer allocator.free(project_head_after);
    try std.testing.expectEqualSlices(u8, project_head_before, project_head_after);
}

test "the config.worktree redirect stays closed even when a project has extensions.worktreeConfig on but no config.worktree of its own yet" {
    // The reviewer's own reproduction of Finding 1: a project with
    // extensions.worktreeConfig already on, but with no config.worktree of
    // its own, is exactly the shape where `git worktree add` leaves a
    // linked worktree with no config.worktree either. From inside a real
    // sandbox, the reviewer wrote core.fsmonitor and core.hooksPath into
    // that path, then ran an ordinary git status on the host, against that
    // worktree, and watched the marker file the fsmonitor line named
    // appear: host code execution, chosen entirely by the agent. This test
    // drives the same shape end to end and confirms the fix closes it: the
    // write from inside the sandbox is refused, and a host side git status
    // afterward runs nothing the agent chose.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    // Turn the extension on, but never set a value with --worktree: the
    // main checkout's own .git/config.worktree is then never written, the
    // premise the reviewer's reproduction depends on.
    var config_output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "config", "extensions.worktreeConfig", "true",
    }, null);
    defer config_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, config_output.term);

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const wt = workspace.kind.worktree;
    // Confirm the premise before trusting the rest of this test: this
    // worktree really has no config.worktree of its own, only create's own
    // scratch stand-in for one.
    try std.testing.expect(wt.worktree_config_worktree_is_scratch);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "write", wt.worktree_config_worktree_target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);

    // Belt and suspenders, the way the reviewer proved the hole in the
    // first place: an ordinary git status on the host, against the
    // worktree itself, must run cleanly and touch nothing the agent chose.
    var status_output = try git.run(allocator, std.testing.io, &project.env, wt.path, &.{"status"}, null);
    defer status_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, status_output.term);

    // The file behind the mount is still create's own empty scratch file,
    // not a core.hooksPath or a core.fsmonitor the agent would have had git
    // run on this very status call.
    const contents = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, wt.worktree_config_worktree_source, allocator, .limited(4096));
    defer allocator.free(contents);
    try std.testing.expectEqual(@as(usize, 0), contents.len);
}

/// Sum the "count:" and "in-pack:" lines of `git count-objects -v` at
/// `root_path`: the total number of objects the repository holds on disk,
/// loose or packed. Used to prove a sandboxed git call never added anything
/// to the real object store, whatever it wrote into its own scratch one.
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

/// The exact bytes `git show-ref` prints at `root_path`: every ref the
/// repository has and what it points at. Used to prove a sandboxed git call
/// never moved a ref of the real repository. The caller owns the returned
/// slice.
fn captureRefs(allocator: std.mem.Allocator, env: *const std.process.Environ.Map, root_path: []const u8) ![]u8 {
    var output = try git.run(allocator, std.testing.io, env, root_path, &.{"show-ref"}, null);
    defer output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    return allocator.dupe(u8, output.stdout);
}

/// The number of regular files anywhere under `root_path`, walked
/// recursively. Used to prove the scratch object store actually gained a
/// file: a passing "git-commit" probe run that wrote nothing there would be
/// proving nothing about the scratch store at all.
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
        // A skip needs no message: a test that writes to standard error and
        // passes still puts a `failed command:` line in the build log.
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

    // Fresh content: never committed before, so git cannot skip writing the
    // object because it already has one with this hash. See
    // escape_probe.zig's own doc comment on commit_test_file.
    var new_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const new_file_path = try std.fmt.bufPrintZ(&new_file_buffer, "{s}/chock-object-store-test.txt", .{wt.path});
    try writeFile(std.testing.io, new_file_path, "chock overlay tamper\n");

    const scratch_files_before = try countRegularFiles(allocator, wt.object_store_source);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "git-commit", git_path);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    // The scratch store, on the host, actually gained files: the new blob,
    // the new tree, and the new commit object all had to land somewhere,
    // and GIT_OBJECT_DIRECTORY said it was here.
    const scratch_files_after = try countRegularFiles(allocator, wt.object_store_source);
    try std.testing.expect(scratch_files_after > scratch_files_before);

    // The real repository, on the host, gained nothing: neither a new
    // object nor a moved ref. The worktree was created detached, so the
    // commit only ever updated the worktree's own HEAD file, never a ref
    // under the real repository's own refs/heads.
    const objects_after = try countRealObjects(allocator, &project.env, project.root_path);
    try std.testing.expectEqual(objects_before, objects_after);
    const refs_after = try captureRefs(allocator, &project.env, project.root_path);
    defer allocator.free(refs_after);
    try std.testing.expectEqualStrings(refs_before, refs_after);
}

test "an agent that renames its own GIT_ALTERNATE_OBJECT_DIRECTORIES gains nothing: it can still commit, but can no longer read history it did not just write" {
    // The security question a renamed alternate asks: the alternates
    // mechanism is a variable that names a path git reads
    // objects from, the same category as commondir and config.worktree,
    // both of which gave an attacker host code execution in earlier
    // reviews. Can the agent change where the alternate points, and if so,
    // what does that get it?
    //
    // The answer this test proves, not just argues: yes, the agent can
    // change it, because it is an ordinary environment variable and the
    // agent can set one on any subprocess of its own. But changing it gets
    // the agent nothing useful. git never writes to an alternate, only
    // reads from one, so no value of this variable ever grants a write the
    // mount layer would otherwise refuse: GIT_OBJECT_DIRECTORY, fixed by
    // the sandbox's own mount list to the scratch store, is what decides
    // where a write lands, never the alternate. The only thing tampering
    // with it changes is what that one command can read: this probe run
    // still commits successfully, exactly like the test above, but the
    // read of the pre-existing parent commit, the one from before this
    // session started, now fails, because the tampered alternate no longer
    // names a real path. See escape_probe.zig's own runGitCommitFlow for
    // the exact sequence.
    const allocator = std.testing.allocator;

    const git_path = (try findGitOnPath(allocator, std.testing.io)) orelse {
        // A skip needs no message: a test that writes to standard error and
        // passes still puts a `failed command:` line in the build log.
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

    // escape_probe.zig's own git-alternate-tamper op runs add and commit
    // (which must still succeed) and then drops the real
    // GIT_ALTERNATE_OBJECT_DIRECTORIES this test's own workspace.sandboxConfig
    // built, replacing it with a bogus path, before reading the
    // pre-existing parent commit (which must now fail). Exit 0 means both
    // halves happened exactly as predicted; see escape_probe.zig's own top
    // comment for what any other exit code would mean.
    const term = try runProbe(allocator, &workspace, root_tmp, "git-alternate-tamper", git_path);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    // Belt and suspenders, the same as every other escape test here: the
    // real repository still gained nothing, whether or not the tampering
    // itself succeeded.
    const objects_after = try countRealObjects(allocator, &project.env, project.root_path);
    try std.testing.expectEqual(objects_before, objects_after);
    const refs_after = try captureRefs(allocator, &project.env, project.root_path);
    defer allocator.free(refs_after);
    try std.testing.expectEqualStrings(refs_before, refs_after);
}

/// The nested "work" directory overlayfs itself creates inside `ov.work` for
/// its own bookkeeping is left behind with mode 0000. `std.testing.tmpDir`'s
/// own cleanup cannot delete a directory it cannot even read. Put the
/// permission back before `tmpDir.cleanup` ever tries. Best effort: the
/// directory may not exist at all if the mount itself never happened. The
/// same fix `overlay.zig`'s and `Workspace.zig`'s own tests already carry,
/// under the same name, for the same reason.
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

    // The write landed in the worktree, on the host.
    const in_worktree = try std.fs.path.join(allocator, &.{ wt.path, "chock-abstraction-proof.txt" });
    defer allocator.free(in_worktree);
    _ = try std.Io.Dir.cwd().statFile(std.testing.io, in_worktree, .{});

    // The user's real project never gained the file: the agent was never in
    // that tree at all.
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

    // Same three calls as the worktree test above: open, sandboxConfig
    // (inside runProbe), spawn. Nothing here asks which kind Workspace.open
    // picked.
    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;
    try std.testing.expect(workspace.kind == .overlay);

    const ov = workspace.kind.overlay;
    const target = try std.fs.path.join(allocator, &.{ ov.project, "chock-abstraction-proof.txt" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    const term = try runProbe(allocator, &workspace, root_tmp, "write", target);
    // A real overlay mount, made by chock-sandbox's own buildRoot, leaves
    // its own scratch "work" directory mode 0000 on the host: the same fix
    // overlay.zig's and Workspace.zig's own tests already carry, under the
    // same name, for the same reason. Put the permission back before
    // tmp.cleanup runs, whether or not the probe itself succeeded, or this
    // leaves an undeletable directory under .zig-cache/tmp.
    allowScratchCleanup(allocator, ov);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    // The write landed in the overlay's own upper layer, on the host: this
    // is the real mount `chock-sandbox`'s own buildRoot performed, inside
    // the sandbox this probe spawned, proving the overlay-kind Mount entry
    // sandboxConfig described was not just a description but a mount a real
    // sandbox actually made.
    const in_upper = try std.fs.path.join(allocator, &.{ ov.upper, "chock-abstraction-proof.txt" });
    defer allocator.free(in_upper);
    _ = try std.Io.Dir.cwd().statFile(std.testing.io, in_upper, .{});

    // The user's real project, the overlay's own read only lower layer,
    // never gained the file.
    const in_project = try std.fs.path.join(allocator, &.{ project.root_path, "chock-abstraction-proof.txt" });
    defer allocator.free(in_project);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, in_project, .{}),
    );
}

test "a denied file cannot be read by a real tool call, and reads as the notice" {
    // **The whole claim, end to end.** `secret.env` is committed, so the
    // worktree checkout really holds it and the mount is the only thing
    // between a tool call and its bytes. Exit code 1 means the read landed on
    // `namespace.deny_notice` and not on `secret_content`.
    //
    // Mutation check: drop the `.deny` append in `Workspace.sandboxConfig`,
    // or the deny pass in `buildRoot`, and this probe reads the real secret
    // and exits 0.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.initWith(allocator, tmp, chock_zon_with_deny);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    // The premise, before anything is trusted: the checkout really did get
    // the secret, so the refusal below is about a file that is there.
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
    // **The other half of the test above, and it is not decoration.** A probe
    // that answered "not the notice" for every path, or a mount tree that
    // covered the whole project, would let the test above pass while breaking
    // every session. This reads `tracked.txt` through the very same config and
    // requires exit 0: bytes that are neither empty nor the notice.
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
    // **The lapse this design refuses to have.** `.env` is in no commit, so
    // the checkout has no such file, and a denial that only covered files that
    // already exist would protect nothing the moment the agent, or the user,
    // made one. `chock-sandbox`'s own `applyDenyMounts` makes an empty file to
    // bind over instead, so the name is covered before anything runs.
    //
    // Two probes, because one would not settle it. The read must give the
    // notice, and the write must be refused with EROFS: a mount that existed
    // but was writable would let an agent put its own content there and read
    // it back, which is harmless in itself but would mean the mount is not
    // read only, and a later denial of a real file would inherit that.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.initWith(allocator, tmp, chock_zon_with_deny);
    defer project.deinit();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    // The premise: the checkout really has no `.env` of its own.
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

    // And what that costs, written down rather than left to be discovered: the
    // empty file `applyDenyMounts` made to bind over is still in the checkout
    // after the sandbox is gone. It is one empty file, with a name the project
    // itself asked to deny, and it reaches the user's repository through
    // nothing but a commit. See `applyDenyMounts`'s own doc comment.
    const left_behind = try std.Io.Dir.cwd().statFile(std.testing.io, in_checkout, .{});
    try std.testing.expectEqual(@as(u64, 0), left_behind.size);
}

test "a denied file cannot be deleted, so an agent cannot uncover it" {
    // A whiteout or an unlink would take the mount away and leave the real
    // file, or the empty placeholder, in its place. It cannot: the path is
    // itself a mount point, and unlinking one answers EBUSY. The same fact
    // `chock.zon` already relies on, now relied on by every denied path.
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
    // **The list is fixed when the workspace opens, and no later read of any
    // `chock.zon` can move it.** This writes a `chock.zon` with no `deny_read`
    // at all straight into the checkout, on the host, which is a stronger move
    // than the agent itself can make from inside the sandbox, where that path
    // is a read only mount point, and then runs `sandboxConfig` again, which
    // is what every tool call of a real session does.
    //
    // **What this pins, said exactly.** Nothing re-reads the block today, so
    // this holds for a `Workspace.open` that read the checkout as readily as
    // for one that read the project. It is here to fail the day somebody adds
    // that re-read to `sandboxConfig`, which is the one change that would turn
    // an edit made mid session into a way out of the block. The test that
    // catches a reader pointed at the wrong copy **today** is the `adopt` one
    // at the end of this file, where the checkout really does carry the edited
    // file by the time the list is read: point `adopt` at `wt.path` and it
    // fails while this one still passes.
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
    // The edit really happened, so the refusal below is not a fact about a
    // write that quietly failed.
    const after = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, edited, allocator, .limited(4096));
    defer allocator.free(after);
    try std.testing.expectEqualStrings(chock_zon_content, after);

    const target = try std.fs.path.join(allocator, &.{ workspace.kind.worktree.project_root, "secret.env" });
    defer allocator.free(target);

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();

    // `sandboxConfig` runs again inside `runProbe`, after the edit, which is
    // exactly what happens on every tool call of a real session.
    const term = try runProbe(allocator, &workspace, root_tmp, "read", target);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a project that denies nothing gets no deny mount and reads its files as before" {
    // **The case that must cost nothing**, because it is every project that
    // exists today. The mount list carries no `.deny` entry at all, so
    // `applyDenyMounts` returns before it makes any file, and a read of the
    // very file another project denies comes back whole.
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
    // A project with no git of its own gets one overlay mount over the whole
    // tree, so its secret is reachable through a different mount from the
    // worktree kind's. The denial is the same pass either way, which is the
    // point of applying it after every other mount rather than beside them.
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

    // **And the secret was not copied up.** A mount target opened with
    // `O_CREAT` would make overlayfs copy the lower file into the upper layer,
    // which puts the very bytes this exists to hide into the session's own
    // scratch directory on the host. `applyDenyMounts` reads the kind with
    // `statx` and never opens an existing target, and this is that rule
    // measured rather than argued.
    const in_upper = try std.fs.path.join(allocator, &.{ ov.upper, "secret.env" });
    defer allocator.free(in_upper);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, in_upper, .{}),
    );
}

test "a deny_read entry that names a directory refuses the whole session, by name" {
    // `~/.aws` is a directory and `.env` is a file, and this design supports
    // only the second. A refusal by name, before any workspace is built, is
    // the honest answer: a covered directory would read as "this project keeps
    // no credentials here", which is the confusion the notice file exists to
    // avoid and which an empty directory has no room for.
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
    // The handover case. `adopt` runs against a checkout a whole session has
    // already worked in, so the `chock.zon` in it is whatever that session
    // left. Reading the deny list from there would make handing over a way out
    // of the block, which is the same fault `findChockZonForAdopt` answers for
    // the policy file itself.
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
