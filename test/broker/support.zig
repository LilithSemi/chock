//! What both broker test roots in this directory need to build a scratch
//! project and to drive `test/workspace/escape_probe.zig`.
//!
//! `test/broker/actions.zig` and `test/broker/git_shim.zig` are each their
//! own test root, so neither can import the other. This file is a sibling of
//! both, inside the same module directory, so a plain relative `@import`
//! reaches it from either one and neither has to keep its own copy.
//!
//! It holds no test of its own on purpose. A test here would be compiled and
//! run once for every root that imports it.

const std = @import("std");
const chock_workspace = @import("chock-workspace");
const sandbox = @import("chock-sandbox");

const git = chock_workspace.git;
const Workspace = chock_workspace.Workspace;
const testing = std.testing;

// Zig 0.16 removed the argv access that would let a test take a path at run
// time, and the default test runner panics on any argv it does not
// recognize, so build.zig embeds the probe's path as a build time constant.
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
    // **A git that failed says why in the failure itself.** This comparison
    // is reached only when git already exited non zero, and
    // `expectEqualStrings` prints both sides, so git's own message is part of
    // the failure. Written to standard error instead, it would reach the
    // build log of every passing run of this suite as well, and `zig build`
    // prints a `failed command:` line for any run step that wrote there.
    if (output.term != .exited or output.term.exited != 0) {
        try testing.expectEqualStrings("", output.stderr);
    }
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    return gpa.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

/// A fresh repository with one commit, plus an empty scratch directory
/// beside it. The same shape `lib/chock-broker/actions.zig`'s own tests and
/// `test/workspace/escape.zig` both build, kept here rather than shared
/// because neither of those files is a module this one can import.
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

/// Find `git` on this process's own PATH, the same binary the dev shell put
/// there for every other git call in this project. Null when it is not
/// there, so the one test that binds a real git into a sandbox can skip
/// cleanly rather than fail for a reason unrelated to what it pins.
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
/// `workspace`'s own `Sandbox.Config`, inside `root_tmp`. Nothing in this
/// test binary calls `Sandbox.spawn`; the probe does.
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

    // **The probe's standard error goes nowhere, and that is deliberate.**
    // The probe reports through its exit status, which is the only thing any
    // caller here reads, and its standard error carries its own commentary
    // plus whatever the sandboxed program writes: a real `git` inside the
    // sandbox says a great deal there while doing exactly what the test
    // wants. Inherited, all of it lands on this test binary's own standard
    // error, and `zig build` prints a `failed command:` line for any run step
    // that wrote there, whatever its exit status.
    var child = try std.process.spawn(testing.io, .{
        .argv = &.{ escape_probe_path, op, root_path, config.cwd, mounts_blob, rules_blob, env_blob, target },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    return child.wait(testing.io);
}
