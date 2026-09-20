//! The two streams of the real `chock` binary, read apart. A unit test cannot
//! see this: `tty.streams` falls back to sending every row to standard error,
//! so a `main` that never called `tty.useStreams` passes every test in
//! `src/tty.zig`. Only a real process has a real fd 1 and a real fd 2.
//!
//! The last test builds a project whose provider cannot be reached, so a real
//! session starts, calls the model, fails to connect and writes its own ending.

const std = @import("std");
const builtin = @import("builtin");
const chock_path = @import("chock_path").chock_path;
/// Found by `build.zig`, which has an environment to search. Empty when there is
/// none, and the one test that needs it then skips.
const git_path = @import("chock_path").git_path;
/// The one thing read from the program's own source. `src/main.zig` pins it
/// against `build.zig.zon` off the disk, so this compares the binary to the
/// manifest. Everything else here is written out, because a test that imports
/// what the program prints agrees with itself for ever.
const version_line = @import("chock_main").version_line;

const testing = std.testing;

/// A ULID in Crockford base32, which is what `session.isValidId` accepts.
const session_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

const Run = struct {
    out: []u8,
    err: []u8,
    code: u8,

    fn deinit(self: *Run, gpa: std.mem.Allocator) void {
        gpa.free(self.out);
        gpa.free(self.err);
    }
};

/// No command here can crash, and no `Exit` member uses this code.
const did_not_exit: u8 = 255;

fn codeOf(term: std.process.Child.Term) u8 {
    return switch (term) {
        .exited => |status| status,
        else => did_not_exit,
    };
}

fn runChock(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    args: []const []const u8,
) !Run {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.append(gpa, chock_path);
    try argv.appendSlice(gpa, args);

    const result = try std.process.run(gpa, io, .{
        .argv = argv.items,
        .environ_map = env,
    });
    return .{ .out = result.stdout, .err = result.stderr, .code = codeOf(result.term) };
}

/// `std.process.SpawnOptions.StdIo.file` passes the same open file as both
/// descriptors, so what comes back is the order the program really wrote in.
fn runOntoOneFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    env: *const std.process.Environ.Map,
    args: []const []const u8,
) ![]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.append(gpa, chock_path);
    try argv.appendSlice(gpa, args);

    var file = try dir.createFile(io, name, .{ .read = true });
    defer file.close(io);

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .environ_map = env,
        .stdin = .ignore,
        .stdout = .{ .file = file },
        .stderr = .{ .file = file },
    });
    _ = try child.wait(io);

    return dir.readFileAlloc(io, name, gpa, .limited(1024 * 1024));
}

/// The environment is built from nothing, not copied from the person running the
/// suite, so a `NO_COLOR` or a `TERM` of theirs cannot decide the answer.
const Sandbox = struct {
    tmp: testing.TmpDir,
    env: std.process.Environ.Map,
    root: []u8,

    fn init(gpa: std.mem.Allocator, io: std.Io) !Sandbox {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        // The child has its own working directory, so every path is absolute.
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try tmp.dir.realPath(io, &buffer);
        const root = try gpa.dupe(u8, buffer[0..length]);
        errdefer gpa.free(root);

        var env = std.process.Environ.Map.init(gpa);
        errdefer env.deinit();
        try env.put("HOME", root);
        try env.put("XDG_DATA_HOME", root);
        try env.put("XDG_CONFIG_HOME", root);
        try env.put("XDG_CACHE_HOME", root);
        try env.put("XDG_STATE_HOME", root);
        return .{ .tmp = tmp, .env = env, .root = root };
    }

    fn deinit(self: *Sandbox, gpa: std.mem.Allocator) void {
        gpa.free(self.root);
        self.env.deinit();
        self.tmp.cleanup();
    }
};

/// Read back out of the program's own message. A second copy of
/// `session.projectKey` would agree with itself for ever.
fn sessionDirOf(gpa: std.mem.Allocator, io: std.Io, box: *Sandbox) ![]u8 {
    var told = try runChock(gpa, io, &box.env, &.{ "plan", "--project", box.root });
    defer told.deinit(gpa);

    const open = std.mem.indexOfScalar(u8, told.err, '(') orelse return error.NoDirectoryNamed;
    const close = std.mem.indexOfScalarPos(u8, told.err, open, ')') orelse return error.NoDirectoryNamed;
    return gpa.dupe(u8, told.err[open + 1 .. close]);
}

test "a diagnostic is on standard error while standard output stays empty" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{ "sessions", "--project", box.root });
    defer run.deinit(gpa);

    try testing.expectEqualStrings("", run.out);
    try testing.expect(std.mem.indexOf(u8, run.err, "no sessions") != null);
    try testing.expectEqual(@as(u8, 0), run.code);
}

test "the help a person asked for is on standard output and the help after a mistyped command is on standard error" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();

    var asked = try runChock(gpa, io, &env, &.{"--help"});
    defer asked.deinit(gpa);
    try testing.expect(std.mem.indexOf(u8, asked.out, "Usage: chock <command>") != null);
    try testing.expectEqualStrings("", asked.err);
    try testing.expectEqual(@as(u8, 0), asked.code);

    var mistyped = try runChock(gpa, io, &env, &.{"nonesuch"});
    defer mistyped.deinit(gpa);
    try testing.expectEqualStrings("", mistyped.out);
    try testing.expect(std.mem.indexOf(u8, mistyped.err, "there is no command named") != null);
    try testing.expect(std.mem.indexOf(u8, mistyped.err, "Usage: chock <command>") != null);
    try testing.expectEqual(@as(u8, 1), mistyped.code);
}

test "a piped stream gets no escape sequence, and --color=always still paints one" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    // Both streams are pipes here, because `std.process.run` gives them pipes.
    try box.env.put("TERM", "xterm-256color");

    var piped = try runChock(gpa, io, &box.env, &.{"nonesuch"});
    defer piped.deinit(gpa);
    try testing.expect(piped.err.len != 0);
    try testing.expect(std.mem.indexOfScalar(u8, piped.err, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, piped.out, 0x1b) == null);

    var loud = try runChock(gpa, io, &box.env, &.{ "nonesuch", "--color=always" });
    defer loud.deinit(gpa);
    try testing.expect(std.mem.indexOfScalar(u8, loud.err, 0x1b) != null);
    try testing.expect(std.mem.indexOf(u8, loud.err, "there is no command named") != null);

    try box.env.put("CLICOLOR_FORCE", "1");
    var forced = try runChock(gpa, io, &box.env, &.{ "nonesuch", "--color=never" });
    defer forced.deinit(gpa);
    try testing.expect(std.mem.indexOfScalar(u8, forced.err, 0x1b) == null);

    var encouraged = try runChock(gpa, io, &box.env, &.{"nonesuch"});
    defer encouraged.deinit(gpa);
    try testing.expect(std.mem.indexOfScalar(u8, encouraged.err, 0x1b) != null);

    var rows = try runChock(gpa, io, &box.env, &.{ "--help", "--color=always" });
    defer rows.deinit(gpa);
    try testing.expect(rows.out.len != 0);
    try testing.expect(std.mem.indexOfScalar(u8, rows.out, 0x1b) == null);
}

test "standard output is flushed before standard error, so one file holds them in the written order" {
    // Standard output is buffered and standard error is not, so without the
    // `flushOut()` in `tty.print` the warning reaches the file first.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    const session_dir = try sessionDirOf(gpa, io, &box);
    defer gpa.free(session_dir);

    // A line with no newline after it is what a crash mid write leaves.
    try std.Io.Dir.cwd().createDirPath(io, session_dir);
    const log_path = try std.fmt.allocPrint(gpa, "{s}/{s}.jsonl", .{ session_dir, session_id });
    defer gpa.free(log_path);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = log_path,
        .data = "{\"chock_log\":1}\n{\"id\":0,\"at_ms\":0,\"event\":{\"session\":{\"start\"",
    });

    const both = try runOntoOneFile(
        gpa,
        io,
        box.tmp.dir,
        "one-terminal.txt",
        &box.env,
        &.{ "plan", "show", session_id, "--project", box.root },
    );
    defer gpa.free(both);

    const row = std.mem.indexOf(u8, both, "kept no task list") orelse {
        try testing.expectEqualStrings("kept no task list", both);
        return error.NoRowWritten;
    };
    const warning = std.mem.indexOf(u8, both, "ends mid write") orelse {
        try testing.expectEqualStrings("ends mid write", both);
        return error.NoWarningWritten;
    };

    try testing.expect(row < warning);

    const header = std.mem.indexOf(u8, both, session_id) orelse return error.NoHeaderWritten;
    try testing.expect(header < row);
}

test "every command still exits with the code it did, including the refusals" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    const cases = [_]struct {
        args: []const []const u8,
        want: u8,
        why: []const u8,
    }{
        .{ .args = &.{"--version"}, .want = 0, .why = "a version was asked for and given" },
        .{ .args = &.{"help"}, .want = 0, .why = "help was asked for and given" },
        .{ .args = &.{"nonesuch"}, .want = 1, .why = "there is no such command" },
        // The flag comes after the command: `main` reads the command first and
        // hands the rest to `takeGlobalFlags`.
        .{ .args = &.{ "sessions", "--color=maybe" }, .want = 1, .why = "--color took a value it does not have" },
        .{ .args = &.{"askpass"}, .want = 1, .why = "the helper takes one prompt and was given none" },
        .{ .args = &.{ "doctor", "--help" }, .want = 0, .why = "help was asked for and given" },
        .{ .args = &.{ "doctor", "list" }, .want = 1, .why = "chock doctor takes no subcommand" },
    };

    for (cases) |case| {
        var run = try runChock(gpa, io, &box.env, case.args);
        defer run.deinit(gpa);
        var wanted_buffer: [160]u8 = undefined;
        var got_buffer: [160]u8 = undefined;
        const wanted = try std.fmt.bufPrint(
            &wanted_buffer,
            "chock {s} exits {d}, because {s}",
            .{ case.args[0], case.want, case.why },
        );
        const got = try std.fmt.bufPrint(
            &got_buffer,
            "chock {s} exits {d}, because {s}",
            .{ case.args[0], run.code, case.why },
        );
        try testing.expectEqualStrings(wanted, got);
    }

    var did_nothing = try runChock(gpa, io, &box.env, &.{ "cache", "clear", "--project", box.root });
    defer did_nothing.deinit(gpa);
    try testing.expect(did_nothing.code != 0);
    try testing.expectEqualStrings("", did_nothing.out);
}

/// Spelled here rather than imported: this file holds nothing of the built
/// binary's own source.
const alt_screen_on = "\x1b[?1049h";

const Project = struct {
    path: []u8,

    /// Port 1 on the loopback address. Nothing listens there, and nothing may:
    /// it is below the range an unprivileged program can bind.
    const dead_provider = "http://127.0.0.1:1/v1";

    fn make(gpa: std.mem.Allocator, io: std.Io, box: *Sandbox) !Project {
        // `Sandbox` builds its environment from nothing, so the workspace builder
        // would find no `git`. `PATH` and nothing else.
        try box.env.put("PATH", std.fs.path.dirname(git_path) orelse "/usr/bin");

        const config_dir = try std.fmt.allocPrint(gpa, "{s}/chock", .{box.root});
        defer gpa.free(config_dir);
        try std.Io.Dir.cwd().createDirPath(io, config_dir);

        const config_path = try std.fmt.allocPrint(gpa, "{s}/config.zon", .{config_dir});
        defer gpa.free(config_path);
        // Readable by nobody else, which `chock-auth` insists on for a token.
        var file = try std.Io.Dir.createFileAbsolute(io, config_path, .{ .permissions = @enumFromInt(0o600) });
        defer file.close(io);
        var buffer: [512]u8 = undefined;
        var writer = file.writerStreaming(io, &buffer);
        try writer.interface.print(
            \\.{{
            \\    .providers = .{{
            \\        .{{ .name = "dead", .kind = "openai-compat", .base_url = "{s}",
            \\           .context_tokens = 65536, .token = "sk-not-a-real-key" }},
            \\    }},
            \\    .defaults = .{{ .provider = "dead", .model = "no-such-model" }},
            \\}}
            \\
        , .{dead_provider});
        try writer.interface.flush();

        const path = try std.fmt.allocPrint(gpa, "{s}/project", .{box.root});
        errdefer gpa.free(path);
        try std.Io.Dir.cwd().createDirPath(io, path);
        const readme = try std.fmt.allocPrint(gpa, "{s}/README.md", .{path});
        defer gpa.free(readme);
        try std.Io.Dir.cwd().writeFile(io, .{
            .sub_path = readme,
            .data = "a project with one commit\n",
        });

        // `git worktree add` checks a commit out, so the repository needs one.
        // The identity is on the command line, so no git configuration is read.
        try git(gpa, io, git_path, &box.env, path, &.{ "init", "--quiet", "." });
        try git(gpa, io, git_path, &box.env, path, &.{ "add", "-A" });
        try git(gpa, io, git_path, &box.env, path, &.{
            "-c",     "user.email=test@example.invalid",
            "-c",     "user.name=test",
            "commit", "--quiet",
            "-m",     "one",
        });
        return .{ .path = path };
    }

    fn deinit(self: *Project, gpa: std.mem.Allocator) void {
        gpa.free(self.path);
    }

    fn git(
        gpa: std.mem.Allocator,
        io: std.Io,
        program: []const u8,
        env: *const std.process.Environ.Map,
        cwd: []const u8,
        args: []const []const u8,
    ) !void {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.append(gpa, program);
        try argv.appendSlice(gpa, args);
        const result = std.process.run(gpa, io, .{
            .argv = argv.items,
            .environ_map = env,
            .cwd = .{ .path = cwd },
        }) catch |err| {
            try testing.expectEqualStrings(args[0], @errorName(err));
            return err;
        };
        defer gpa.free(result.stdout);
        defer gpa.free(result.stderr);
        if (codeOf(result.term) != 0) {
            try testing.expectEqualStrings("a git subcommand that exits zero", args[0]);
            return error.GitFailed;
        }
    }
};

test "chock run never takes the alternate screen, whatever the colour flags say" {
    // The `session.end` line below is what stops this passing for a command that
    // stopped before the decision. The session builds a git worktree, so a
    // machine with no `git` skips rather than reports success.
    if (git_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    try box.env.put("TERM", "xterm-256color");

    var project = try Project.make(gpa, io, &box);
    defer project.deinit(gpa);

    for ([_][]const []const u8{
        &.{ "run", "--project", project.path, "--", "fix", "the", "parser" },
        &.{ "run", "--color=always", "--project", project.path, "--", "fix", "the", "parser" },
    }) |args| {
        var one = try runChock(gpa, io, &box.env, args);
        defer one.deinit(gpa);

        try testing.expect(std.mem.indexOf(u8, one.out, "chock: session ended") != null);

        try testing.expect(std.mem.indexOf(u8, one.out, alt_screen_on) == null);
        try testing.expect(std.mem.indexOf(u8, one.err, alt_screen_on) == null);
    }
}

/// Three files rather than pipes, because `std.process.RunOptions` has no way to
/// give a child its standard input. A file is a stream that is not a terminal.
fn runChockOnStdin(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    message: []const u8,
    args: []const []const u8,
) !Run {
    // Absolute, because the child starts somewhere else. `chock_path` is a build
    // output path, relative to the directory the suite runs in.
    var suite_dir = try std.Io.Dir.cwd().openDir(io, ".", .{});
    defer suite_dir.close(io);
    var here: [std.fs.max_path_bytes]u8 = undefined;
    const length = try suite_dir.realPath(io, &here);
    const program = try std.fs.path.resolve(gpa, &.{ here[0..length], chock_path });
    defer gpa.free(program);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.append(gpa, program);
    try argv.appendSlice(gpa, args);

    try dir.writeFile(io, .{ .sub_path = "message.txt", .data = message });
    const message_file = try dir.openFile(io, "message.txt", .{});
    defer message_file.close(io);
    var out_file = try dir.createFile(io, "stdout.txt", .{ .read = true });
    defer out_file.close(io);
    var err_file = try dir.createFile(io, "stderr.txt", .{ .read = true });
    defer err_file.close(io);

    var child = std.process.spawn(io, .{
        .argv = argv.items,
        .environ_map = env,
        .cwd = .{ .path = cwd },
        .stdin = .{ .file = message_file },
        .stdout = .{ .file = out_file },
        .stderr = .{ .file = err_file },
    }) catch |err| {
        try testing.expectEqualStrings(program, @errorName(err));
        return err;
    };
    const term = try child.wait(io);

    const out = try dir.readFileAlloc(io, "stdout.txt", gpa, .limited(1024 * 1024));
    errdefer gpa.free(out);
    const err = try dir.readFileAlloc(io, "stderr.txt", gpa, .limited(1024 * 1024));
    return .{ .out = out, .err = err, .code = codeOf(term) };
}

test "a message on standard input runs a session with no display and no escape byte" {
    if (git_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    try box.env.put("TERM", "xterm-256color");

    var project = try Project.make(gpa, io, &box);
    defer project.deinit(gpa);

    // No arguments, because bare `chock` is the command. A word after it would
    // be a command name, so the project is named by the working directory.
    var piped = try runChockOnStdin(
        gpa,
        io,
        box.tmp.dir,
        &box.env,
        project.path,
        "fix the parser\n",
        &.{},
    );
    defer piped.deinit(gpa);

    try testing.expect(std.mem.indexOf(u8, piped.out, "chock: session ended") != null);
    try testing.expect(std.mem.indexOf(u8, piped.err, "Usage: chock <command>") == null);

    try testing.expect(std.mem.indexOfScalar(u8, piped.out, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, piped.err, 0x1b) == null);

    const header = "model no-such-model via dead";
    try testing.expect(std.mem.indexOf(u8, piped.err, header) != null);
    try testing.expect(std.mem.indexOf(u8, piped.out, header) == null);
}

/// Read rather than listed, so this tracks `chock run` instead of holding a
/// second copy of its options. A name ends at the first `=` or space.
fn optionsRunAdvertises(gpa: std.mem.Allocator, text: []const u8) ![]const []const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    errdefer found.deinit(gpa);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const body = std.mem.trimStart(u8, line, " ");
        // Indented, so a prose sentence opening with a dash is not an entry.
        if (body.len == line.len) continue;
        if (!std.mem.startsWith(u8, body, "--")) continue;

        var end: usize = 0;
        while (end < body.len and body[end] != '=' and body[end] != ' ') end += 1;
        try found.append(gpa, body[0..end]);
    }
    return found.toOwnedSlice(gpa);
}

test "every option chock run advertises is an option on bare chock, and not a missing command" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var help = try runChock(gpa, io, &box.env, &.{ "run", "--help" });
    defer help.deinit(gpa);
    const options = try optionsRunAdvertises(gpa, help.out);
    defer gpa.free(options);

    try testing.expect(options.len >= 5);

    for (options) |option| {
        var bare = try runChock(gpa, io, &box.env, &.{option});
        defer bare.deinit(gpa);
        var wanted: [96]u8 = undefined;
        var got: [96]u8 = undefined;
        const said_no_command = std.mem.indexOf(u8, bare.err, "there is no command named") != null;
        try testing.expectEqualStrings(
            try std.fmt.bufPrint(&wanted, "chock {s} is an option", .{option}),
            try std.fmt.bufPrint(&got, "chock {s} is {s}", .{
                option,
                if (said_no_command) "read as a command name" else "an option",
            }),
        );
    }
}

test "an option nobody knows gets the same answer from bare chock as from chock run" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var bare = try runChock(gpa, io, &box.env, &.{"--no-such-option"});
    defer bare.deinit(gpa);
    var through_run = try runChock(gpa, io, &box.env, &.{ "run", "--no-such-option" });
    defer through_run.deinit(gpa);

    try testing.expectEqualStrings(through_run.err, bare.err);
    try testing.expectEqual(through_run.code, bare.code);
    try testing.expect(std.mem.indexOf(u8, bare.err, "--no-such-option") != null);
    try testing.expect(std.mem.indexOf(u8, bare.err, "there is no command named") == null);
}

test "the two words chock answers itself still open with a dash and are still not options" {
    // `--help` and `--version` are `src/main.zig`'s own, so the rule that an
    // option is not a command name has to let them through.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var helped = try runChock(gpa, io, &box.env, &.{"--help"});
    defer helped.deinit(gpa);
    try testing.expect(std.mem.indexOf(u8, helped.out, "Usage: chock <command>") != null);
    try testing.expectEqual(@as(u8, 0), helped.code);

    var versioned = try runChock(gpa, io, &box.env, &.{"--version"});
    defer versioned.deinit(gpa);
    try testing.expectEqualStrings(version_line ++ "\n", versioned.out);
    try testing.expectEqualStrings("", versioned.err);
    try testing.expectEqual(@as(u8, 0), versioned.code);

    var missing = try runChock(gpa, io, &box.env, &.{"nonesuch"});
    defer missing.deinit(gpa);
    try testing.expect(std.mem.indexOf(u8, missing.err, "there is no command named") != null);
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) return;
    return sayWhatItSaid(haystack, needle);
}

fn expectMissing(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) return;
    return sayWhatItSaid(haystack, needle);
}

/// `expectEqualStrings` prints both sides, so the report a real process wrote
/// lands inside the failure. Nothing here may write to standard error:
/// `zig build` reads a run step that does as a failed command.
fn sayWhatItSaid(haystack: []const u8, needle: []const u8) !void {
    try testing.expectEqualStrings(needle, haystack);
    return error.TestUnexpectedResult;
}

const doctor_refusal = "a session cannot start here";

const doctor_first_run_heading = "Before a first run";

const doctor_layers_heading = "Sandbox layers";

/// The names differ by platform because the mechanisms differ: a user namespace,
/// Landlock and seccomp are Linux calls that no macOS release has. Written out
/// rather than read from `src/doctor.zig`, because a test that imported the
/// constant the program prints would agree with itself for ever.
const doctor_layer_names: []const []const u8 = switch (builtin.os.tag) {
    .macos => &.{
        "seatbelt",
        "network",
        "signal reach",
        "ipc",
        "rlimit floor",
        "memory ceiling",
        "mapped memory",
        "process count",
        "disk cap tmpfs",
        "syscall filter",
        "process list",
        "workspace mount",
        "tool call",
    },
    else => &.{
        "user namespace",
        "mount namespace",
        "pid namespace",
        "ipc namespace",
        "net namespace",
        "landlock",
        "seccomp",
        "write^execute",
        "pidfd",
        "cgroup v2",
        "overlayfs",
        "disk cap tmpfs",
    },
};

const doctor_absent_layer_names: []const []const u8 = switch (builtin.os.tag) {
    .macos => &.{ "seatbelt", "rlimit floor", "signal reach" },
    else => &.{ "landlock", "seccomp", "write^execute" },
};

test "chock doctor refuses a machine that cannot run a session, with a code a script can read" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{ "doctor", "--project", box.root });
    defer run.deinit(gpa);

    // 2 is `Exit.faulted`: a first run cannot work here.
    try testing.expectEqual(@as(u8, 2), run.code);
    try testing.expect(run.code != 0);
    try testing.expect(run.code != 1);

    try testing.expectEqualStrings(version_line, std.mem.sliceTo(run.out, '\n'));

    try expectContains(run.out, doctor_first_run_heading);
    try expectContains(run.out, "credential");
    try expectContains(run.out, "workspace space");

    try expectContains(run.err, doctor_refusal);
    try expectMissing(run.out, doctor_refusal);

    try testing.expect(std.mem.indexOfScalar(u8, run.out, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, run.err, 0x1b) == null);

    const counted = std.mem.count(u8, run.out, "BLOCKED");
    try testing.expect(counted >= 1);

    // The word appears in no sentence, so counting it counts the column.
    const marker = "Rows that stop a first run: ";
    const at = std.mem.indexOf(u8, run.err, marker).? + marker.len;
    const footer = try std.fmt.parseInt(usize, std.mem.sliceTo(run.err[at..], ' '), 10);
    try testing.expectEqual(footer, counted);
}

test "chock doctor prints a column of layers or the one sentence about the driver, never both" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{ "doctor", "--project", box.root });
    defer run.deinit(gpa);

    const has_layers = std.mem.indexOf(u8, run.out, doctor_layers_heading) != null;
    const refuses_outright = std.mem.indexOf(u8, run.err, "applies no layer") != null;
    try testing.expect(has_layers != refuses_outright);

    if (has_layers) {
        for (doctor_layer_names) |name| {
            try expectContains(run.out, name);
        }
    } else {
        try expectContains(run.err, "Sandbox.spawn refuses");
        try expectContains(run.err, "permanent");
        // This host's own names: a Linux name on a Mac would be absent anyway.
        for (doctor_absent_layer_names) |name| {
            try expectMissing(run.out, name);
        }
    }
}

test "chock doctor leaves nothing of its own behind" {
    // The kernel makes the overlay's own `work/work` with mode 0, which stops a
    // plain `deleteTree` halfway.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{ "doctor", "--project", box.root });
    defer run.deinit(gpa);

    const session_dir = try sessionDirOf(gpa, io, &box);
    defer gpa.free(session_dir);

    // The probe tree carries the running process's id, so this test cannot name
    // it: a name built here would agree with itself for ever.
    var opened = try std.Io.Dir.openDirAbsolute(io, session_dir, .{ .iterate = true });
    defer opened.close(io);
    var it = opened.iterate();
    while (try it.next(io)) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "doctor.probe")) continue;
        try testing.expectEqualStrings("", entry.name);
    }
}
