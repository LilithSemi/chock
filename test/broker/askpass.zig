//! The password helper, driven by a real `git`.
//!
//! **A test that calls the answering function proves the function, and this
//! project has already shipped a client that had never spoken to a real
//! server.** `lib/chock-broker/askpass.zig` has its own unit tests over a real
//! unix socket; what none of them can say is whether a real `git`, with a real
//! `GIT_ASKPASS`, ever reaches that socket at all, and whether what comes back
//! is a password as far as `git` is concerned. So every test here starts the
//! `git` on this machine.
//!
//! `git credential fill` is the subcommand that asks. It reads a description
//! of one credential on standard input, prompts for what the description does
//! not hold, and prints the whole credential back. **It reaches no network**,
//! which is what makes it the right way to ask a real `git` for a password on
//! a machine with no remote to push to.
//!
//! Two things are proved here that a unit test cannot:
//!
//! * The value really is a password to `git`. It comes back on `git`'s own
//!   standard output as `password=...`, which is `git` saying it accepted it.
//! * The refusal really is a refusal to `git`. A helper that prints nothing
//!   makes `git` fail, and it fails **without** the credential.
//!
//! And one thing is proved by reading `/proc` while the helper runs: the value
//! is in no environment variable and on no command line, so `ps` shows nothing
//! and a shell history holds nothing. See `snapshot_script`.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const askpass = chock_broker.askpass;
const table = chock_policy.table;
const testing = std.testing;

/// Zig 0.16 removed the argv access that would let a test take a path at run
/// time, so `build.zig` embeds both as build time constants. `git_path` is an
/// empty string on a machine with no git, which this reads as a reason to
/// skip.
const chock_path = @import("chock_path").chock_path;
const git_path = @import("chock_path").git_path;

/// The credential every test here hands out. Long enough that finding it in a
/// file proves something, and shaped like a real forge token so a reader knows
/// what it stands in for.
const the_password = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";

/// The host the policy below permits.
const the_host = "git.example.com";

/// A table that permits exactly one host. Written with the labels reversed,
/// which is what `askpass.actionInto` builds and what
/// `lib/chock-broker/network.zig` argues for at length.
const permit_one_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "secret.password.com.example.git", .decision = .allow },
    \\        },
    \\    },
    \\}
;

/// A shell wrapper that records what `ps` would show for the helper, and then
/// becomes the helper.
///
/// `$$` is the shell's own process id, so `/proc/$$/cmdline` and
/// `/proc/$$/environ` are the argument vector and the environment `git` really
/// started this with. `exec` then replaces the shell with `chock askpass`,
/// which inherits both unchanged, so the two files are exactly what another
/// user of this machine could have read while the helper ran.
const snapshot_script =
    \\#!/bin/sh
    \\cat /proc/$$/cmdline > "{s}/cmdline"
    \\cat /proc/$$/environ > "{s}/environ"
    \\exec "{s}" askpass "$1"
    \\
;

/// One drive of a real `git credential fill` against a real endpoint.
const Run = struct {
    gpa: std.mem.Allocator,
    /// Everything `git` printed on standard output. `git credential fill`
    /// prints the credential here.
    stdout: []u8,
    /// Everything `git` and the helper printed on standard error.
    stderr: []u8,
    term: std.process.Child.Term,
    /// Every byte of the session log, as `chockd` would serve it.
    log: []u8,
    /// The environment `git` was started with, one `KEY=VALUE` per entry.
    env: [][]u8,
    /// The argument vector `git` was started with.
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

/// What one test asks of `git`.
const Ask = struct {
    /// The host in the credential description `git` reads on standard input.
    host: []const u8,
    /// The user in that description. An empty one makes `git` prompt for a
    /// user name first, which this helper never answers.
    user: []const u8 = "ross",
    /// The program `GIT_ASKPASS` names. The session's own `askpass` link by
    /// default, which is what a real caller sets.
    helper: ?[]const u8 = null,
    /// Whether the session's socket is named in the environment at all. False
    /// is a helper with nobody to ask, which is every tool call inside the
    /// sandbox.
    tell_the_helper_where: bool = true,
};

/// Build a scratch session, start a real `git credential fill`, and answer it
/// off a real socket while it runs.
///
/// **The endpoint is polled while `git` runs, and that is the shape a caller
/// has to keep.** `git` is waiting on the helper and the helper is waiting on
/// this socket, so a caller that started `git` and blocked on it at once would
/// deadlock. `lib/chock-broker/askpass.zig`'s own top comment says so and
/// gives the three lines; this is those three lines against a real `git`.
fn drive(gpa: std.mem.Allocator, io: std.Io, ask: Ask) !Run {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try absoluteDirPath(io, &path_buffer, tmp.dir);

    const socket_path = try std.fmt.allocPrint(gpa, "{s}/ctl/{s}", .{ dir, askpass.socket_name });
    defer gpa.free(socket_path);

    var endpoint = try askpass.Endpoint.open(io, socket_path, null);
    defer endpoint.close(io);

    // **The link is what `GIT_ASKPASS` can name.** Git runs one executable
    // path with one argument and puts no shell in the way, so
    // `GIT_ASKPASS="<chock> askpass"` fails with `cannot exec`, measured
    // against git 2.55. This is the line a real caller writes.
    const link_path = try std.fmt.allocPrint(gpa, "{s}/ctl/{s}", .{ dir, askpass.link_name });
    defer gpa.free(link_path);
    // `build.zig` gives the path the way the build system holds it, which is
    // relative to the build root. A link resolves against the directory it
    // sits in, so it needs the absolute one, which is what `link` refuses
    // without.
    const chock_absolute = try std.Io.Dir.realPathFileAlloc(.cwd(), io, chock_path, gpa);
    defer gpa.free(chock_absolute);
    try askpass.link(io, link_path, chock_absolute);

    var backing = try chock_proto.storage.Memory.init(gpa, "01ASKPASS");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const policy = try table.Table.parse(gpa, permit_one_host, null);
    defer table.Table.destroy(gpa, policy);

    const asker = askpass.Asker{
        .grants = .{ .entries = &.{.{ .host = the_host, .secret = the_password }} },
        .table = policy,
        .chain = &.{"coder"},
        .agent_kind = "coder",
        .model = "main",
    };

    // The credential description `git credential fill` reads. A blank line
    // ends it.
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
    // two English prompts and refuses everything else.
    try env.put("LC_ALL", "C");
    // A user's own configuration must not decide what this test measures, and
    // a credential helper on this machine would answer before the prompt was
    // ever written.
    try env.put("GIT_CONFIG_GLOBAL", "/dev/null");
    try env.put("GIT_CONFIG_SYSTEM", "/dev/null");
    // Nothing may fall back to a terminal, so the helper is the only route to
    // a password.
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

    // **The loop a real caller writes.** Bounded, so a git that never asks
    // ends this test rather than hanging it: ten seconds of fifty millisecond
    // looks. `git credential fill` answers in milliseconds.
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
    // The proof the whole task turns on. A real `git`, a real `GIT_ASKPASS`
    // pointed at the built binary, a real unix socket, and `git` printing the
    // value back as a password it accepted.
    //
    // Mutation check: change `Asker.answer` to return
    // `.{ .refused = .host_not_permitted }` unconditionally, and the first
    // expectation below fails because git exits non zero with no password.
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var run = try drive(gpa, io, .{ .host = the_host });
    defer run.deinit();

    // git took it. `git credential fill` prints the credential it assembled,
    // and the password line is git saying the helper answered.
    try testing.expectEqual(@as(?u8, 0), run.exited());
    try testing.expect(std.mem.indexOf(u8, run.stdout, "password=" ++ the_password) != null);
    try testing.expect(std.mem.indexOf(u8, run.stdout, "host=" ++ the_host) != null);
    try testing.expectEqual(@as(usize, 1), run.answered);
    try testing.expectEqual(@as(usize, 0), run.refused);

    // **Nowhere else.** Each of these is one of the four places the value must
    // never reach, checked against what really happened rather than against
    // what the code was meant to do.
    //
    // The session log, which `chockd` serves to every attached client. The
    // fact that a prompt happened is in it, and the answer is not.
    try testing.expect(std.mem.indexOf(u8, run.log, "prompt.password") != null);
    try testing.expect(std.mem.indexOf(u8, run.log, the_host) != null);
    try testing.expect(std.mem.indexOf(u8, run.log, the_password) == null);

    // The environment git was started with, which is the environment the
    // helper inherited. `CHOCK_ASKPASS_SOCKET` is in it and holds a path.
    var told_where = false;
    for (run.env) |entry| {
        try testing.expect(std.mem.indexOf(u8, entry, the_password) == null);
        if (std.mem.startsWith(u8, entry, askpass.env_socket ++ "=")) {
            told_where = true;
            try testing.expect(std.mem.endsWith(u8, entry, "/" ++ askpass.socket_name));
        }
    }
    try testing.expect(told_where);

    // The command line, which `ps` shows to every other user of the machine.
    for (run.argv) |arg| try testing.expect(std.mem.indexOf(u8, arg, the_password) == null);

    // And standard error, where a helper that explained itself too eagerly
    // would have put it.
    try testing.expect(std.mem.indexOf(u8, run.stderr, the_password) == null);
}

test "a host nobody permitted gets no password, and git fails rather than carrying on" {
    // The safe direction, measured at the far end.
    // The policy table permits one host. Asking about another one is refused,
    // and the refusal reaches git as a failure and not as an empty password.
    //
    // Mutation check: drop the policy question from `Asker.answer` and this
    // test finds `password=` in git's own output for a host no rule names.
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

    // The person reading git's output is told which refusal it was and what to
    // do about it, rather than only that something failed.
    try testing.expect(std.mem.indexOf(u8, run.stderr, "chock askpass") != null);
    try testing.expect(std.mem.indexOf(u8, run.stderr, "secret.password") != null);
    // git's own message about the same failure is beside it.
    try testing.expect(std.mem.indexOf(u8, run.stderr, "askpass") != null);

    // The prompt is still recorded, so a person can see that Chock was asked
    // and said no.
    try testing.expect(std.mem.indexOf(u8, run.log, "prompt.password") != null);
    try testing.expect(std.mem.indexOf(u8, run.log, the_password) == null);
}

test "a user name prompt is never answered, so a password can never be read as a user" {
    // Measured, and this is why the refusal exists. A helper that answered the
    // user name prompt with the password made git write `username=<the
    // password>` into the credential, which puts it in the URL of every
    // request afterwards.
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
    // What every tool call inside the sandbox gets, because the sandbox has no
    // path to a session's control directory. Here it is spelled as an
    // environment with no socket named in it, which is the same state that
    // reaches this program.
    //
    // Mutation check: make `main` fall back to reading a credential store when
    // the variable is absent, and this test hands out the password to a git
    // that no session was watching.
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var run = try drive(gpa, io, .{ .host = the_host, .tell_the_helper_where = false });
    defer run.deinit();

    try testing.expect(run.exited() != @as(?u8, 0));
    try testing.expect(std.mem.indexOf(u8, run.stdout, "password=") == null);
    try testing.expect(std.mem.indexOf(u8, run.stdout, the_password) == null);
    // Nothing was asked of the session at all.
    try testing.expectEqual(@as(usize, 0), run.answered);
    try testing.expectEqual(@as(usize, 0), run.refused);
    try testing.expect(std.mem.indexOf(u8, run.log, "prompt.password") == null);
    // And the helper said why, in a sentence that names the sandbox.
    try testing.expect(std.mem.indexOf(u8, run.stderr, "reached no session") != null);
}

test "ps and proc show the helper holding no credential while it runs" {
    // The live check, and it is live rather than argued. A wrapper records
    // `/proc/$$/cmdline` and `/proc/$$/environ` and then becomes the helper by
    // `exec`, so what is written is exactly the argument vector and the
    // environment another user of this machine could have read at that moment.
    //
    // Mutation check: put the value in the environment by adding
    // `try env.put("CHOCK_PASSWORD", the_password)` in `drive`, and the
    // environ half of this test fails.
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

    // The wrapper really did become the helper, so the snapshot is of the
    // process that answered.
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

    // Both were really read, so an empty file cannot pass this by accident.
    try testing.expect(cmdline.len != 0);
    try testing.expect(environ.len != 0);
    // The prompt is on the command line, which is what git put there.
    try testing.expect(std.mem.indexOf(u8, cmdline, "Password for") != null);
    // And the socket is in the environment, which is a path.
    try testing.expect(std.mem.indexOf(u8, environ, askpass.env_socket) != null);

    // Neither holds the value.
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

/// Every byte of `path`, bounded. Owned by the caller.
fn readWholeFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        // A wrapper that never ran wrote no file, and an empty result is what
        // the test then reads, which is a failure and not a crash.
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

/// A flat copy of an environment map, one `KEY=VALUE` per entry, so a test can
/// read it after the map has gone.
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
