//! The password helper, driven by the real `git` on this machine. `git
//! credential fill` reaches no network, so it is the way to ask a real `git`
//! for a password with no remote to push to.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const askpass = chock_broker.askpass;
const table = chock_policy.table;
const testing = std.testing;

/// `build.zig` embeds both as build time constants, because the Zig 0.16 test
/// runner takes no argument. An empty `git_path` is a reason to skip.
const chock_path = @import("chock_path").chock_path;
const git_path = @import("chock_path").git_path;

const the_password = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";

const the_host = "git.example.com";

const permit_one_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "secret.password.com.example.git", .decision = .allow },
    \\        },
    \\    },
    \\}
;

/// A shell wrapper that records what `ps` would show for the helper, then
/// becomes the helper. `$$` is the shell's own process id, and `exec` keeps
/// the argument vector and the environment `git` really started it with.
const snapshot_script =
    \\#!/bin/sh
    \\cat /proc/$$/cmdline > "{s}/cmdline"
    \\cat /proc/$$/environ > "{s}/environ"
    \\exec "{s}" askpass "$1"
    \\
;

const Run = struct {
    gpa: std.mem.Allocator,
    stdout: []u8,
    stderr: []u8,
    term: std.process.Child.Term,
    log: []u8,
    env: [][]u8,
    argv: []const []const u8,
    answered: usize,
    refused: usize,

    fn deinit(self: *Run) void {
        self.gpa.free(self.stdout);
        self.gpa.free(self.stderr);
        self.gpa.free(self.log);
        for (self.env) |entry| self.gpa.free(entry);
        self.gpa.free(self.env);
    }

    fn exited(self: Run) ?u8 {
        return switch (self.term) {
            .exited => |code| code,
            else => null,
        };
    }
};

const Ask = struct {
    host: []const u8,
    user: []const u8 = "ross",
    helper: ?[]const u8 = null,
    tell_the_helper_where: bool = true,
    policy: [:0]const u8 = permit_one_host,
};

const deny_the_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "secret.password.com.example.git", .decision = .deny },
    \\        },
    \\    },
    \\}
;

/// The endpoint is polled while `git` runs. `git` waits on the helper and the
/// helper waits on this socket, so a caller that blocked on `git` would deadlock.
fn drive(gpa: std.mem.Allocator, io: std.Io, ask: Ask) !Run {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try absoluteDirPath(io, &path_buffer, tmp.dir);

    const socket_path = try std.fmt.allocPrint(gpa, "{s}/ctl/{s}", .{ dir, askpass.socket_name });
    defer gpa.free(socket_path);

    var endpoint = try askpass.Endpoint.open(io, socket_path, null);
    defer endpoint.close(io);

    // Git runs one executable path with one argument and puts no shell in the
    // way, so `GIT_ASKPASS="<chock> askpass"` fails with `cannot exec` on git
    // 2.55. `build.zig` gives a path relative to the build root, and a link
    // resolves against the directory it sits in, so it needs the absolute one.
    const link_path = try std.fmt.allocPrint(gpa, "{s}/ctl/{s}", .{ dir, askpass.link_name });
    defer gpa.free(link_path);
    const chock_absolute = try std.Io.Dir.realPathFileAlloc(.cwd(), io, chock_path, gpa);
    defer gpa.free(chock_absolute);
    try askpass.link(io, link_path, chock_absolute);

    var backing = try chock_proto.storage.Memory.init(gpa, "01ASKPASS");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const policy = try table.Table.parse(gpa, ask.policy, null);
    defer table.Table.destroy(gpa, policy);

    const asker = askpass.Asker{
        .grants = .{ .entries = &.{.{ .host = the_host, .secret = the_password }} },
        .table = policy,
        .chain = &.{"coder"},
        .agent_kind = "coder",
        .model = "main",
    };

    const description = if (ask.user.len == 0)
        try std.fmt.allocPrint(gpa, "protocol=https\nhost={s}\n\n", .{ask.host})
    else
        try std.fmt.allocPrint(gpa, "protocol=https\nhost={s}\nusername={s}\n\n", .{ ask.host, ask.user });
    defer gpa.free(description);

    const in_path = try std.fmt.allocPrint(gpa, "{s}/in", .{dir});
    defer gpa.free(in_path);
    try writeFileAbsolute(io, in_path, description);

    const out_path = try std.fmt.allocPrint(gpa, "{s}/out", .{dir});
    defer gpa.free(out_path);
    const err_path = try std.fmt.allocPrint(gpa, "{s}/err", .{dir});
    defer gpa.free(err_path);

    var stdin = try std.Io.Dir.openFileAbsolute(io, in_path, .{});
    defer stdin.close(io);
    var stdout = try std.Io.Dir.createFileAbsolute(io, out_path, .{});
    defer stdout.close(io);
    var stderr = try std.Io.Dir.createFileAbsolute(io, err_path, .{});
    defer stderr.close(io);

    var env = try std.testing.environ.createMap(gpa);
    defer env.deinit();
    // git must answer in the C locale, because `askpass.readPrompt` reads the
    // two English prompts. It must read no user configuration and fall back to
    // no terminal, so the helper is the only route to a password.
    try env.put("LC_ALL", "C");
    try env.put("GIT_CONFIG_GLOBAL", "/dev/null");
    try env.put("GIT_CONFIG_SYSTEM", "/dev/null");
    try env.put("GIT_TERMINAL_PROMPT", "0");
    try env.put("GIT_ASKPASS", ask.helper orelse link_path);
    if (ask.tell_the_helper_where) try env.put(askpass.env_socket, socket_path);

    const argv = [_][]const u8{ git_path, "credential", "fill" };

    var child = try std.process.spawn(io, .{
        .argv = &argv,
        .cwd = .{ .path = dir },
        .environ_map = &env,
        .stdin = .{ .file = stdin },
        .stdout = .{ .file = stdout },
        .stderr = .{ .file = stderr },
    });

    // Bounded, so a git that never asks ends this test rather than hanging it.
    for (0..200) |_| {
        _ = try endpoint.step(gpa, io, &locked, asker, 50);
        if (endpoint.answered + endpoint.refused > 0) break;
    }
    const term = try child.wait(io);

    var out = Run{
        .gpa = gpa,
        .stdout = try readWholeFile(gpa, io, out_path),
        .stderr = try readWholeFile(gpa, io, err_path),
        .term = term,
        .log = try gpa.dupe(u8, backing.bytes.items),
        .env = try copyEnv(gpa, &env),
        .argv = &.{},
        .answered = endpoint.answered,
        .refused = endpoint.refused,
    };
    errdefer out.deinit();
    // A copy, because `argv` above is a stack array of this function.
    out.argv = &.{ "git", "credential", "fill" };
    return out;
}

test "a real git asks over the socket and gets the password, and the value is nowhere else" {
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var run = try drive(gpa, io, .{ .host = the_host });
    defer run.deinit();

    try testing.expectEqual(@as(?u8, 0), run.exited());
    try testing.expect(std.mem.indexOf(u8, run.stdout, "password=" ++ the_password) != null);
    try testing.expect(std.mem.indexOf(u8, run.stdout, "host=" ++ the_host) != null);
    try testing.expectEqual(@as(usize, 1), run.answered);
    try testing.expectEqual(@as(usize, 0), run.refused);

    try testing.expect(std.mem.indexOf(u8, run.log, "prompt.password") != null);
    try testing.expect(std.mem.indexOf(u8, run.log, the_host) != null);
    try testing.expect(std.mem.indexOf(u8, run.log, the_password) == null);

    var told_where = false;
    for (run.env) |entry| {
        try testing.expect(std.mem.indexOf(u8, entry, the_password) == null);
        if (std.mem.startsWith(u8, entry, askpass.env_socket ++ "=")) {
            told_where = true;
            try testing.expect(std.mem.endsWith(u8, entry, "/" ++ askpass.socket_name));
        }
    }
    try testing.expect(told_where);

    for (run.argv) |arg| try testing.expect(std.mem.indexOf(u8, arg, the_password) == null);

    try testing.expect(std.mem.indexOf(u8, run.stderr, the_password) == null);
}

test "a host nobody typed a password for gets none, and git fails rather than carrying on" {
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var run = try drive(gpa, io, .{ .host = "evil.test" });
    defer run.deinit();

    try testing.expect(run.exited() != @as(?u8, 0));
    try testing.expect(std.mem.indexOf(u8, run.stdout, "password=") == null);
    try testing.expect(std.mem.indexOf(u8, run.stdout, the_password) == null);
    try testing.expectEqual(@as(usize, 0), run.answered);
    try testing.expectEqual(@as(usize, 1), run.refused);

    try testing.expect(std.mem.indexOf(u8, run.stderr, "chock askpass") != null);
    try testing.expect(std.mem.indexOf(u8, run.stderr, "nobody typed a password") != null);
    try testing.expect(std.mem.indexOf(u8, run.stderr, "askpass") != null);

    try testing.expect(std.mem.indexOf(u8, run.log, "prompt.password") != null);
    try testing.expect(std.mem.indexOf(u8, run.log, the_password) == null);
}

test "a host the policy denies gets no password even when somebody typed one" {
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var run = try drive(gpa, io, .{ .host = the_host, .policy = deny_the_host });
    defer run.deinit();

    try testing.expect(run.exited() != @as(?u8, 0));
    try testing.expect(std.mem.indexOf(u8, run.stdout, "password=") == null);
    try testing.expect(std.mem.indexOf(u8, run.stdout, the_password) == null);
    try testing.expectEqual(@as(usize, 0), run.answered);
    try testing.expectEqual(@as(usize, 1), run.refused);

    try testing.expect(std.mem.indexOf(u8, run.stderr, "secret.password") != null);
    try testing.expect(std.mem.indexOf(u8, run.log, the_password) == null);
}

test "a user name prompt is never answered, so a password can never be read as a user" {
    // A helper that answered the user name prompt with the password made git
    // write `username=<the password>`, which puts it in every later URL.
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var run = try drive(gpa, io, .{ .host = the_host, .user = "" });
    defer run.deinit();

    try testing.expect(run.exited() != @as(?u8, 0));
    try testing.expect(std.mem.indexOf(u8, run.stdout, the_password) == null);
    try testing.expectEqual(@as(usize, 0), run.answered);
    try testing.expectEqual(@as(usize, 1), run.refused);
    try testing.expect(std.mem.indexOf(u8, run.stderr, "https://you@") != null);
}

test "a helper with no session to ask answers nothing at all" {
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var run = try drive(gpa, io, .{ .host = the_host, .tell_the_helper_where = false });
    defer run.deinit();

    try testing.expect(run.exited() != @as(?u8, 0));
    try testing.expect(std.mem.indexOf(u8, run.stdout, "password=") == null);
    try testing.expect(std.mem.indexOf(u8, run.stdout, the_password) == null);
    try testing.expectEqual(@as(usize, 0), run.answered);
    try testing.expectEqual(@as(usize, 0), run.refused);
    try testing.expect(std.mem.indexOf(u8, run.log, "prompt.password") == null);
    try testing.expect(std.mem.indexOf(u8, run.stderr, "reached no session") != null);
}

test "ps and proc show the helper holding no credential while it runs" {
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try absoluteDirPath(io, &path_buffer, tmp.dir);

    const script_path = try std.fmt.allocPrint(gpa, "{s}/snapshot.sh", .{dir});
    defer gpa.free(script_path);
    const chock_absolute = try std.Io.Dir.realPathFileAlloc(.cwd(), io, chock_path, gpa);
    defer gpa.free(chock_absolute);
    const script = try std.fmt.allocPrint(gpa, snapshot_script, .{ dir, dir, chock_absolute });
    defer gpa.free(script);
    try writeFileAbsolute(io, script_path, script);
    try setExecutable(io, script_path);

    var run = try drive(gpa, io, .{ .host = the_host, .helper = script_path });
    defer run.deinit();

    try testing.expectEqual(@as(?u8, 0), run.exited());
    try testing.expect(std.mem.indexOf(u8, run.stdout, "password=" ++ the_password) != null);

    const cmdline_path = try std.fmt.allocPrint(gpa, "{s}/cmdline", .{dir});
    defer gpa.free(cmdline_path);
    const environ_path = try std.fmt.allocPrint(gpa, "{s}/environ", .{dir});
    defer gpa.free(environ_path);

    const cmdline = try readWholeFile(gpa, io, cmdline_path);
    defer gpa.free(cmdline);
    const environ = try readWholeFile(gpa, io, environ_path);
    defer gpa.free(environ);

    try testing.expect(cmdline.len != 0);
    try testing.expect(environ.len != 0);
    try testing.expect(std.mem.indexOf(u8, cmdline, "Password for") != null);
    try testing.expect(std.mem.indexOf(u8, environ, askpass.env_socket) != null);

    try testing.expect(std.mem.indexOf(u8, cmdline, the_password) == null);
    try testing.expect(std.mem.indexOf(u8, environ, the_password) == null);
}

fn absoluteDirPath(io: std.Io, buffer: []u8, dir: std.Io.Dir) ![:0]u8 {
    const len = try dir.realPath(io, buffer);
    buffer[len] = 0;
    return buffer[0..len :0];
}

fn writeFileAbsolute(io: std.Io, path: []const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

fn setExecutable(io: std.Io, path: []const u8) !void {
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o700));
}

fn readWholeFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return gpa.dupe(u8, ""),
        else => |e| return e,
    };
    defer file.close(io);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var buffer: [4096]u8 = undefined;
    while (out.items.len < 1 << 20) {
        const count = file.readStreaming(io, &.{&buffer}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        if (count == 0) break;
        try out.appendSlice(gpa, buffer[0..count]);
    }
    return out.toOwnedSlice(gpa);
}

fn copyEnv(gpa: std.mem.Allocator, env: *const std.process.Environ.Map) ![][]u8 {
    var entries: std.ArrayList([]u8) = .empty;
    errdefer {
        for (entries.items) |entry| gpa.free(entry);
        entries.deinit(gpa);
    }
    var it = env.iterator();
    while (it.next()) |pair| {
        try entries.append(gpa, try std.fmt.allocPrint(gpa, "{s}={s}", .{ pair.key_ptr.*, pair.value_ptr.* }));
    }
    return entries.toOwnedSlice(gpa);
}
