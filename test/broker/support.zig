//! What both broker test roots in this directory need to build a scratch
//! project and to drive `test/workspace/escape_probe.zig`. It holds no test of
//! its own, so no root that imports it compiles a duplicate.

const std = @import("std");
const chock_workspace = @import("chock-workspace");
const sandbox = @import("chock-sandbox");

const git = chock_workspace.git;
const Workspace = chock_workspace.Workspace;
const testing = std.testing;

// Zig 0.16 has no argv a test can read, and the default test runner panics on
// argv it does not know, so build.zig embeds the probe path at build time.
const escape_probe_path = @import("escape_probe_path").escape_probe_path;

pub fn absoluteDirPath(io: std.Io, buffer: []u8, dir: std.Io.Dir) ![:0]u8 {
    const len = dir.realPath(io, buffer) catch return error.RealPathFailed;
    buffer[len] = 0;
    return buffer[0..len :0];
}

pub fn writeFileAbsolute(io: std.Io, path: []const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

/// Run git at `cwd` and require it to exit zero. The trimmed standard output
/// comes back, owned by the caller.
pub fn gitOk(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    argv: []const []const u8,
) ![]u8 {
    var output = try git.run(gpa, testing.io, env, cwd, argv, null);
    defer output.deinit(gpa);
    // `zig build` prints a `failed command:` line for any run step that writes
    // to standard error, so git's message goes into the assertion instead.
    if (output.term != .exited or output.term.exited != 0) {
        try testing.expectEqualStrings("", output.stderr);
    }
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    return gpa.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

/// A fresh repository with one commit, plus an empty scratch directory beside it.
pub const TestProject = struct {
    gpa: std.mem.Allocator,
    root_path: [:0]const u8,
    scratch_path: [:0]const u8,
    env: std.process.Environ.Map,

    pub fn init(gpa: std.mem.Allocator, tmp: std.testing.TmpDir) !TestProject {
        const io = testing.io;
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_path = try absoluteDirPath(io, &buffer, tmp.dir);

        var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const root_path = try std.fmt.bufPrintZ(&root_buffer, "{s}/project", .{tmp_path});
        try std.Io.Dir.createDirAbsolute(io, root_path, .default_dir);

        var scratch_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const scratch_path = try std.fmt.bufPrintZ(&scratch_buffer, "{s}/scratch", .{tmp_path});
        try std.Io.Dir.createDirAbsolute(io, scratch_path, .default_dir);

        var env = try std.testing.environ.createMap(gpa);
        errdefer env.deinit();
        try env.put("GIT_CEILING_DIRECTORIES", tmp_path);

        gpa.free(try gitOk(gpa, &env, root_path, &.{ "init", "-b", "main" }));
        gpa.free(try gitOk(gpa, &env, root_path, &.{ "config", "user.email", "test@example.com" }));
        gpa.free(try gitOk(gpa, &env, root_path, &.{ "config", "user.name", "Test" }));

        var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{root_path});
        try writeFileAbsolute(io, tracked_path, "hello\n");
        gpa.free(try gitOk(gpa, &env, root_path, &.{ "add", "tracked.txt" }));
        gpa.free(try gitOk(gpa, &env, root_path, &.{ "commit", "-m", "first commit" }));

        return .{
            .gpa = gpa,
            .root_path = try gpa.dupeZ(u8, root_path),
            .scratch_path = try gpa.dupeZ(u8, scratch_path),
            .env = env,
        };
    }

    pub fn deinit(self: *TestProject) void {
        self.gpa.free(self.root_path);
        self.gpa.free(self.scratch_path);
        self.env.deinit();
    }
};

/// Find `git` on this process's own PATH. Null lets the caller skip instead of
/// failing for a reason it does not pin.
pub fn findGitOnPath(gpa: std.mem.Allocator, io: std.Io) !?[]u8 {
    const path_env = std.process.Environ.getPosix(std.testing.environ, "PATH") orelse return null;
    var it = std.mem.tokenizeScalar(u8, path_env, ':');
    while (it.next()) |dir| {
        const candidate = try std.fs.path.join(gpa, &.{ dir, "git" });
        if (std.Io.Dir.cwd().statFile(io, candidate, .{})) |_| return candidate else |_| gpa.free(candidate);
    }
    return null;
}

pub fn serializeMounts(gpa: std.mem.Allocator, mounts: []const sandbox.namespace.Mount) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (mounts) |m| {
        const line = switch (m) {
            .bind => |b| try std.fmt.allocPrint(
                gpa,
                "bind\x01{s}\x01{s}\x01{d}\n",
                .{ b.source, b.target, @intFromBool(b.read_only) },
            ),
            .overlay => |o| try std.fmt.allocPrint(
                gpa,
                "overlay\x01{s}\x01{s}\x01{s}\x01{s}\n",
                .{ o.lower, o.upper, o.work, o.target },
            ),
            .proc => |p| try std.fmt.allocPrint(
                gpa,
                "proc\x01{s}\n",
                .{p.target},
            ),
            .deny => |d| try std.fmt.allocPrint(
                gpa,
                "deny\x01{s}\n",
                .{d.target},
            ),
        };
        defer gpa.free(line);
        try out.appendSlice(gpa, line);
    }
    return out.toOwnedSlice(gpa);
}

pub fn serializeRules(gpa: std.mem.Allocator, rules: []const sandbox.Config.Rule) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (rules) |r| {
        const line = try std.fmt.allocPrint(gpa, "{s}\x01{d}\n", .{ r.path, r.access.bits() });
        defer gpa.free(line);
        try out.appendSlice(gpa, line);
    }
    return out.toOwnedSlice(gpa);
}

pub fn serializeEnv(gpa: std.mem.Allocator, env: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (env) |entry| {
        try out.appendSlice(gpa, entry);
        try out.append(gpa, '\n');
    }
    return out.toOwnedSlice(gpa);
}

/// Run `escape_probe` with `op` and `target`, against a sandbox built from
/// `workspace`'s own `Sandbox.Config`. The probe spawns the sandbox, not this
/// binary.
pub fn runProbe(
    gpa: std.mem.Allocator,
    workspace: *const Workspace,
    root_tmp: std.testing.TmpDir,
    op: []const u8,
    target: []const u8,
) !std.process.Child.Term {
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try absoluteDirPath(testing.io, &root_buffer, root_tmp.dir);

    const config = try workspace.sandboxConfig(gpa, root_path);
    defer gpa.free(config.mounts);
    defer gpa.free(config.rules);
    defer gpa.free(config.env);

    const mounts_blob = try serializeMounts(gpa, config.mounts);
    defer gpa.free(mounts_blob);
    const rules_blob = try serializeRules(gpa, config.rules);
    defer gpa.free(rules_blob);
    const env_blob = try serializeEnv(gpa, config.env);
    defer gpa.free(env_blob);

    // A real `git` in the sandbox writes plenty to standard error while doing
    // what the test wants, and `zig build` prints a `failed command:` line for
    // any run step that writes there. The exit status carries the answer.
    var child = try std.process.spawn(testing.io, .{
        .argv = &.{ escape_probe_path, op, root_path, config.cwd, mounts_blob, rules_blob, env_blob, target },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(testing.io);
    try skipIfNothingMeasured(term);
    return term;
}

/// Skip when the probe answered "this machine would not give me a sandbox". A
/// boundary that was never reached is not a boundary that held, so these suites
/// also run in the CI job named "Sandbox", which fails rather than skips.
pub fn skipIfNothingMeasured(term: std.process.Child.Term) !void {
    const code = switch (term) {
        .exited => |c| c,
        else => return,
    };
    if (code == sandbox.namespace.nothing_measured_exit_status) return error.SkipZigTest;
}
