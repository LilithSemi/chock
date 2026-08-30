//! The two streams of the real `chock` binary, read apart.
//!
//! ## Why this cannot be a unit test
//!
//! Every test in `src/tty.zig` sets the two streams itself and then reads what
//! it set. That proves the mechanism and proves nothing about the program: a
//! `main` that never called `tty.useStreams` would pass every one of them,
//! because the fallback in `tty.streams` quietly sends each row to standard
//! error and every unit test would still see what it wrote. Only a real process
//! has a real fd 1 and a real fd 2.
//!
//! So this spawns the built binary and reads its streams. What it pins:
//!
//! * A diagnostic is on standard error while standard output stays empty, so
//!   `chock sessions | grep` reads rows and never a sentence about rows.
//! * A help page a person asked for is on standard output, and the same page
//!   after a mistyped command is on standard error.
//! * A pipe gets no escape sequence, and `--color=always` still paints one, so
//!   the first half is about the rule and not about a program that never
//!   paints.
//! * **With both streams on one file, the bytes are in the order they were
//!   written.** That is the flush gate in `tty.print`, and one file is the only
//!   way to see it: two separate pipes are each correct on their own however
//!   badly they interleave.
//! * Every command exits with the code it always did.
//! * **`chock run` never takes the alternate screen.** The interface is bare
//!   `chock` and `chock run` is the plain command line: see `src/ui.zig`. Only
//!   a real run can say so, because the decision is made inside a session.
//!
//! ## One session is started here, and only one
//!
//! Every command below but the last reads a directory or the command line and
//! answers. The last builds a project and a configuration whose provider cannot
//! be reached, so a real session starts, calls the model, fails to connect and
//! writes its own ending: see `Project`. That is the cheapest session there is
//! and it is what carries the run as far as the display decision.
//!
//! A run that does real work still needs a provider, a sandbox and a model,
//! and that belongs in a real end to end run rather than in `zig build test`.

const std = @import("std");
const builtin = @import("builtin");
const chock_path = @import("chock_path").chock_path;
/// Where `git` is on this machine, found by `build.zig`, which has an
/// environment to search. Empty when there is none, and the one test that needs
/// it then skips. See the option in `build.zig` for why a test cannot find it.
const git_path = @import("chock_path").git_path;
/// The line `chock --version` prints, and the line `chock doctor` opens with.
///
/// **The one thing this file reads from the program's own source.** Every
/// other constant here is written out, because a test that imports what the
/// program prints agrees with itself forever: see `doctor_layer_names`. This
/// one is different, because `src/main.zig` pins it against `build.zig.zon`
/// read off the disk, so comparing the binary's output to it compares the
/// binary to the manifest.
const version_line = @import("chock_main").version_line;

const testing = std.testing;

/// A session identifier this test writes a log under. A ULID in Crockford
/// base32, which is what `session.isValidId` accepts, and `chock plan show`
/// asserts on that before it opens anything.
const session_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

/// What one run of the binary gave back. **The two streams are kept apart**,
/// because keeping them together is the state this file exists to say is over.
const Run = struct {
    out: []u8,
    err: []u8,
    code: u8,

    fn deinit(self: *Run, gpa: std.mem.Allocator) void {
        gpa.free(self.out);
        gpa.free(self.err);
    }
};

/// The exit code of a run that did not exit normally. No command here can
/// crash, and this is not a code any `Exit` member uses, so it reads as wrong
/// in a failure rather than as some ordinary outcome.
const did_not_exit: u8 = 255;

fn codeOf(term: std.process.Child.Term) u8 {
    return switch (term) {
        .exited => |status| status,
        else => did_not_exit,
    };
}

/// Run `chock` with `args` and read the two streams separately.
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

/// Run `chock` with **both streams on one file**, and read that file.
///
/// This is what a terminal is: two descriptors, one place, and therefore one
/// order. `std.process.SpawnOptions.StdIo.file` passes the same open file as
/// both, so what comes back is the order the program really wrote in.
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

/// A directory with nothing of Chock's in it, and an environment that sends
/// every Chock path into it.
///
/// **The environment is built from nothing**, not copied from the person
/// running the suite, so `NO_COLOR` or a `TERM` on their machine cannot decide
/// what these tests measure.
const Sandbox = struct {
    tmp: testing.TmpDir,
    env: std.process.Environ.Map,
    root: []u8,

    fn init(gpa: std.mem.Allocator, io: std.Io) !Sandbox {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        // `realPath` and not a path built from the temporary directory's name:
        // the child is a separate process with its own working directory, so
        // every path this hands it has to be absolute.
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try tmp.dir.realPath(io, &buffer);
        const root = try gpa.dupe(u8, buffer[0..length]);
        errdefer gpa.free(root);

        var env = std.process.Environ.Map.init(gpa);
        errdefer env.deinit();
        // Every one of these is read by `lib/chock-auth/paths.zig`. Setting all
        // of them is what keeps this test off the machine's real state,
        // whatever a platform prefers.
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

/// Where this project's session logs live, asked of the program rather than
/// worked out here.
///
/// `chock plan` on a project with no sessions names the directory in its own
/// message. Reading it back is what keeps this test from holding a second copy
/// of `session.projectKey`, which hashes the project path: a copy would agree
/// with itself forever and stop agreeing with the program.
fn sessionDirOf(gpa: std.mem.Allocator, io: std.Io, box: *Sandbox) ![]u8 {
    var told = try runChock(gpa, io, &box.env, &.{ "plan", "--project", box.root });
    defer told.deinit(gpa);

    const open = std.mem.indexOfScalar(u8, told.err, '(') orelse return error.NoDirectoryNamed;
    const close = std.mem.indexOfScalarPos(u8, told.err, open, ')') orelse return error.NoDirectoryNamed;
    return gpa.dupe(u8, told.err[open + 1 .. close]);
}

test "a diagnostic is on standard error while standard output stays empty" {
    // The point of the whole split, on the real binary. A project with no
    // sessions has no rows, and the sentence saying so is a diagnostic, so
    // `chock sessions | grep` must read nothing at all rather than read a
    // sentence that is not a row.
    //
    // Mutation check: send the "no sessions" line through `tty.out` and
    // standard output stops being empty.
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
    // Finding nothing is still an answer, and the code says so.
    try testing.expectEqual(@as(u8, 0), run.code);
}

test "the help a person asked for is on standard output and the help after a mistyped command is on standard error" {
    // `chock --help | less` has to work, and a script reading standard output
    // must never be handed a help page as if it were an answer.
    //
    // Mutation check: give both calls to `printUsage` one stream and a half of
    // this fails whichever stream is chosen.
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
    // `Exit.usage`, which a mistyped command has always given.
    try testing.expectEqual(@as(u8, 1), mistyped.code);
}

test "a piped stream gets no escape sequence, and --color=always still paints one" {
    // The property `chock usage > costs.txt` needs. `CLICOLOR_FORCE` and a real
    // `TERM` are both set here, so this is the order in `tty.decide` measured
    // end to end: `--color=never` is stronger than either.
    //
    // The second half is what stops the first from passing for no reason. A
    // program that had lost its painter entirely would satisfy "no escapes on a
    // pipe" perfectly.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    // A terminal type good enough for colour, so the only thing left to decide
    // is that neither stream is a terminal. Both are pipes here, because
    // `std.process.run` gives them pipes.
    try box.env.put("TERM", "xterm-256color");

    // A mistyped command, because its refusal carries the `err` rank. A `plain`
    // line writes no escape even with colour fully on, which is the property
    // that lets an unranked call site stay unranked, so a plain line could
    // never tell any of these runs apart.
    //
    // **The default, and no flag at all.** This is what a person piping gets,
    // and it is the case a change to `tty.decide` would break. Mutation check:
    // make `decide` end in `return true` and this half fails.
    var piped = try runChock(gpa, io, &box.env, &.{"nonesuch"});
    defer piped.deinit(gpa);
    try testing.expect(piped.err.len != 0);
    try testing.expect(std.mem.indexOfScalar(u8, piped.err, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, piped.out, 0x1b) == null);

    // Asked for by name, so it arrives. Without this the test above would pass
    // for a program that had lost its painter entirely.
    var loud = try runChock(gpa, io, &box.env, &.{ "nonesuch", "--color=always" });
    defer loud.deinit(gpa);
    try testing.expect(std.mem.indexOfScalar(u8, loud.err, 0x1b) != null);
    // The same bytes are underneath, whatever the painting: a rank changes what
    // wraps a line and never the line.
    try testing.expect(std.mem.indexOf(u8, loud.err, "there is no command named") != null);

    // `--color=never` beats `CLICOLOR_FORCE`, which is the order `tty.decide`
    // keeps, measured through the real command line and the real environment
    // rather than through a `Conditions` value a test made up.
    try box.env.put("CLICOLOR_FORCE", "1");
    var forced = try runChock(gpa, io, &box.env, &.{ "nonesuch", "--color=never" });
    defer forced.deinit(gpa);
    try testing.expect(std.mem.indexOfScalar(u8, forced.err, 0x1b) == null);

    // And with nothing said, `CLICOLOR_FORCE` does reach a pipe, so the line
    // above is about the order and not about a flag that silences everything.
    var encouraged = try runChock(gpa, io, &box.env, &.{"nonesuch"});
    defer encouraged.deinit(gpa);
    try testing.expect(std.mem.indexOfScalar(u8, encouraged.err, 0x1b) != null);

    // The help page is `plain` on standard output, so it stays clean even with
    // colour fully on. That is what a person piping into `grep` depends on.
    var rows = try runChock(gpa, io, &box.env, &.{ "--help", "--color=always" });
    defer rows.deinit(gpa);
    try testing.expect(rows.out.len != 0);
    try testing.expect(std.mem.indexOfScalar(u8, rows.out, 0x1b) == null);
}

test "standard output is flushed before standard error, so one file holds them in the written order" {
    // **The ordering rule, and the only test that can see it end to end.**
    //
    // `chock plan show` on a session that kept no task list and whose log ends
    // mid write says both things: the identifier, the log path, and "kept no
    // task list" on standard output, then the warning about the torn log on
    // standard error. Standard output is buffered and standard error is not, so
    // without the `flushOut()` at the top of `tty.print` the warning reaches the
    // file first and the three lines before it arrive after it.
    //
    // Mutation check: delete that call and the two expectations below swap.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    const session_dir = try sessionDirOf(gpa, io, &box);
    defer gpa.free(session_dir);

    // A log with a torn tail: one line that has no newline after it. That is
    // what a crash mid write leaves, and `chock plan` reads it as incomplete.
    // The line decodes as no plan update, so the task list is empty too, and
    // the command takes the branch that writes to both streams.
    try std.Io.Dir.cwd().createDirPath(io, session_dir);
    const log_path = try std.fmt.allocPrint(gpa, "{s}/{s}.jsonl", .{ session_dir, session_id });
    defer gpa.free(log_path);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = log_path,
        // The header `chock_proto.log.Log.open` insists on, then one line that
        // stops in the middle with no newline after it.
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

    // **Each failure carries the whole file.** Control reaches a block below
    // only when the text is not in `both` at all, so the comparison in it
    // cannot hold, and `expectEqualStrings` prints both sides. That puts what
    // was really written into the failure, where a write to standard error
    // would put it into every passing run of this suite as well: `zig build`
    // reads any run step that wrote there as a failed command.
    const row = std.mem.indexOf(u8, both, "kept no task list") orelse {
        try testing.expectEqualStrings("kept no task list", both);
        return error.NoRowWritten;
    };
    const warning = std.mem.indexOf(u8, both, "ends mid write") orelse {
        try testing.expectEqualStrings("ends mid write", both);
        return error.NoWarningWritten;
    };

    // Written first, so it is in the file first. This is the whole assertion.
    try testing.expect(row < warning);

    // And the identifier, written before either of them, is before both. That
    // says the flush moved everything standard output was holding and not
    // merely the last line of it.
    const header = std.mem.indexOf(u8, both, session_id) orelse return error.NoHeaderWritten;
    try testing.expect(header < row);
}

test "every command still exits with the code it did, including the refusals" {
    // A stream change must not move an exit code. Each of these is a different
    // member of `main.Exit`, and a script reads them: `finished` for a question
    // that was answered, `usage` for a command line that could not be
    // understood, and `usage` again for a subcommand asked to do work it found
    // nothing to do.
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
        // The flag comes after the command, because `main` reads the command
        // first and hands everything after it to `takeGlobalFlags`.
        .{ .args = &.{ "sessions", "--color=maybe" }, .want = 1, .why = "--color took a value it does not have" },
        .{ .args = &.{"askpass"}, .want = 1, .why = "the helper takes one prompt and was given none" },
        .{ .args = &.{ "doctor", "--help" }, .want = 0, .why = "help was asked for and given" },
        .{ .args = &.{ "doctor", "list" }, .want = 1, .why = "chock doctor takes no subcommand" },
    };

    for (cases) |case| {
        var run = try runChock(gpa, io, &box.env, case.args);
        defer run.deinit(gpa);
        // One comparison of two sentences, so a failure names the command,
        // both codes and the reason the code is what it is, all inside the
        // failure itself. `expectEqual` on the two numbers alone would say
        // which case failed only by its position in this table, and a write
        // to standard error would reach the build log of every passing run.
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

    // `chock cache clear` with no cache: a command that did nothing must not
    // report success. Kept apart from the table above because it needs the
    // project, and because this is the rule `src/main.zig`'s own top comment
    // calls the fault that made the Darwin check hollow for weeks.
    var did_nothing = try runChock(gpa, io, &box.env, &.{ "cache", "clear", "--project", box.root });
    defer did_nothing.deinit(gpa);
    try testing.expect(did_nothing.code != 0);
    try testing.expectEqualStrings("", did_nothing.out);
}

/// What a full screen application writes to take the alternate screen. Spelled
/// here rather than imported: this file spawns a built binary and reads its
/// bytes, and holds nothing of that binary's own source.
const alt_screen_on = "\x1b[?1049h";

/// Build a project and a configuration that carry `chock run` all the way to a
/// session, so a test can read what a real session wrote.
///
/// **A provider that cannot be reached is the point.** The session starts, takes
/// its log, calls the model, fails to connect, writes its `session.end` and
/// stops. Everything before the first request has run by then, and the display
/// decision is one of those things.
const Project = struct {
    path: []u8,

    /// Port 1 on the loopback address. Nothing listens there, and nothing may:
    /// it is below the range an unprivileged program can bind.
    const dead_provider = "http://127.0.0.1:1/v1";

    fn make(gpa: std.mem.Allocator, io: std.Io, box: *Sandbox) !Project {
        // `git` is spawned by the workspace builder, and `Sandbox` builds its
        // environment from nothing, so the child would find no `git` at all.
        // **`PATH` and nothing else**: the point of an environment built from
        // nothing is that no variable of the person's own can decide what these
        // tests measure, and where `git` lives decides nothing.
        try box.env.put("PATH", std.fs.path.dirname(git_path) orelse "/usr/bin");

        const config_dir = try std.fmt.allocPrint(gpa, "{s}/chock", .{box.root});
        defer gpa.free(config_dir);
        try std.Io.Dir.cwd().createDirPath(io, config_dir);

        const config_path = try std.fmt.allocPrint(gpa, "{s}/config.zon", .{config_dir});
        defer gpa.free(config_path);
        // Readable by nobody else, which `chock-auth` insists on for a token
        // written in place.
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

        // One commit, because `git worktree add` checks a commit out and a
        // repository with none has nothing to build a workspace from. The
        // identity is on the command line so no global git configuration is
        // read or needed.
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
            // **The failure names the subcommand and the error, and nothing
            // is written to the terminal.** This comparison is reached only
            // when the call already failed, and `expectEqualStrings` prints
            // both sides. Written out instead, the same words would land in
            // the build log of every passing run of this suite, and
            // `zig build` reads any run step that wrote to standard error as
            // a failed command. See the "no test writes to standard error"
            // test in `test/proto/lock.zig`.
            try testing.expectEqualStrings(args[0], @errorName(err));
            return err;
        };
        defer gpa.free(result.stdout);
        defer gpa.free(result.stderr);
        // The same rule: a git that exited non zero says which subcommand it
        // was inside the failure, rather than on the terminal.
        if (codeOf(result.term) != 0) {
            try testing.expectEqualStrings("a git subcommand that exits zero", args[0]);
            return error.GitFailed;
        }
    }
};

test "chock run never takes the alternate screen, whatever the colour flags say" {
    // **The hardest rule the interface has to keep.** `src/ui.zig` draws a full
    // screen display and bare `chock` is where it lives. `chock run` is the
    // plain command line and does not gain one, whatever standard output is.
    // `Options.interface` is what the two share, and this is what says no
    // command line reaches it.
    //
    // **The session really runs**, which is what stops this passing for a
    // command that stopped before the decision. The expectation on the
    // `session.end` line below is that half: a run that never started would
    // fail there rather than pass here quietly.
    //
    // Mutation check: replace the `if (options.interface)` gate in
    // `src/run.zig` with `if (true)` and this fails with the alternate screen
    // in standard output.
    // The session builds a git worktree, so a machine with no `git` cannot run
    // this at all. Skipped rather than passed: a test that quietly reports
    // success for work it did not do is the fault `src/main.zig`'s own top
    // comment calls out.
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

    // `--color=always` is the case that matters: it paints a pipe, and it still
    // must not bring up an application in one.
    for ([_][]const []const u8{
        &.{ "run", "--project", project.path, "--", "fix", "the", "parser" },
        &.{ "run", "--color=always", "--project", project.path, "--", "fix", "the", "parser" },
    }) |args| {
        var one = try runChock(gpa, io, &box.env, args);
        defer one.deinit(gpa);

        // The session started, called the provider, failed to reach it and
        // wrote its own ending. Without this the two lines below would pass
        // for a command that refused before it ever decided anything.
        try testing.expect(std.mem.indexOf(u8, one.out, "chock: session ended") != null);

        try testing.expect(std.mem.indexOf(u8, one.out, alt_screen_on) == null);
        try testing.expect(std.mem.indexOf(u8, one.err, alt_screen_on) == null);
    }
}

/// Run `chock` with a message on standard input, and read the two streams apart.
///
/// **Three files rather than pipes**, because `std.process.RunOptions` has no
/// way to give a child its standard input. A file is a stream that is not a
/// terminal, which is the whole of what this test needs it to be.
fn runChockOnStdin(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    message: []const u8,
    args: []const []const u8,
) !Run {
    // **Absolute, because the child is started somewhere else.** `chock_path`
    // is a build output path, relative to the directory the suite runs in, and
    // a child that changed directory first would not find it.
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
        // The failure names the error inside itself rather than on the
        // terminal, the same way `Project.git` does and for the same reason.
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
    // **The non-interactive path of bare `chock`.** `echo "fix the parser" |
    // chock > answer.txt` takes the message from the stream, runs the session
    // and prints it the way `chock run` would. Neither stream is a terminal
    // here, so nothing may be drawn on either.
    //
    // Only a real process can see this: the decision reads `isTty` on three
    // real descriptors, and a test binary has none of its own to lend.
    //
    // Mutation check: make `src/ui.zig`'s `start` print the usage page for a
    // message it already holds, which is what it did before this, and the first
    // two expectations fail.
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

    // Bare `chock`, with the message on standard input and the project named,
    // because a child has a working directory of its own.
    // **No arguments, because bare `chock` is the command.** A word after it
    // would be a command name, so the project is named by the working
    // directory a child is started in.
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

    // The session started, called the provider it could not reach, and wrote
    // its own ending. Without this the rest would pass for a run that stopped
    // before it decided anything.
    try testing.expect(std.mem.indexOf(u8, piped.out, "chock: session ended") != null);
    // And not the usage page, which is what a run with nothing to do prints.
    try testing.expect(std.mem.indexOf(u8, piped.err, "Usage: chock <command>") == null);

    // Not one escape byte on either stream: no display, no colour, nothing.
    try testing.expect(std.mem.indexOfScalar(u8, piped.out, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, piped.err, 0x1b) == null);

    // **And every diagnostic is still on standard error.** A display folds the
    // lines it is given into its own transcript, which is written to standard
    // output when it comes down: see `src/ui.zig`'s `Diagnostics`. A run with
    // no display must not do that, or `chock > answer.txt` would collect the
    // warnings in the file and leave the terminal silent.
    //
    // The session header names the model and the provider instance, and only
    // this configuration's own two words can produce it, so it cannot be
    // matched by accident.
    //
    // Mutation check: install the diagnostics writer whatever
    // `Options.display` says and the line moves to standard output, failing
    // both halves at once.
    const header = "model no-such-model via dead";
    try testing.expect(std.mem.indexOf(u8, piped.err, header) != null);
    try testing.expect(std.mem.indexOf(u8, piped.out, header) == null);
}

/// The `--option` names `chock run --help` advertises, read out of its own
/// usage text.
///
/// **Read rather than listed**, so this tracks `chock run` instead of being a
/// second copy of its options. A copy is exactly what broke bare `chock` twice:
/// see `main.namesNoCommand`. An option added to `run` tomorrow is covered by
/// this test the day it is added.
///
/// A name is taken up to the first `=` or space, so `--color=<when>` gives
/// `--color`, and a name that takes a value gives the name alone. Both are
/// still not command names, which is the only thing asked of them below.
fn optionsRunAdvertises(gpa: std.mem.Allocator, text: []const u8) ![]const []const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    errdefer found.deinit(gpa);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const body = std.mem.trimStart(u8, line, " ");
        // Indented, so a sentence in the prose that opens with a dash is not
        // mistaken for an entry in the list.
        if (body.len == line.len) continue;
        if (!std.mem.startsWith(u8, body, "--")) continue;

        var end: usize = 0;
        while (end < body.len and body[end] != '=' and body[end] != ' ') end += 1;
        try found.append(gpa, body[0..end]);
    }
    return found.toOwnedSlice(gpa);
}

test "every option chock run advertises is an option on bare chock, and not a missing command" {
    // **The class, not one option.** `chock --verbose` was answered with "there
    // is no command named" until it was fixed by naming two options; then
    // `chock --allow-dirty` was answered the same way, because naming options
    // was the wrong shape. The rule is that an option is not a command name:
    // see `main.namesNoCommand`.
    //
    // Read out of `chock run --help` rather than listed here, so an option
    // added to `run` tomorrow is covered without anybody remembering.
    //
    // Mutation check: list options by name in `namesNoCommand` and every option
    // that list forgets fails here.
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

    // The usage text really does list options, so the loop below is not empty.
    try testing.expect(options.len >= 5);

    for (options) |option| {
        var bare = try runChock(gpa, io, &box.env, &.{option});
        defer bare.deinit(gpa);
        // One comparison, so a failure names the option that broke.
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
    // **One parser, proved rather than agreed.** Two lists of options that
    // happened to match would pass a test that only looked at each on its own;
    // the same bytes from both is what says there is one list.
    //
    // Mutation check: give bare `chock` a parser of its own and the two answers
    // stop matching.
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
    // And it names the option, which "there is no command named" never did.
    try testing.expect(std.mem.indexOf(u8, bare.err, "--no-such-option") != null);
    try testing.expect(std.mem.indexOf(u8, bare.err, "there is no command named") == null);
}

test "the two words chock answers itself still open with a dash and are still not options" {
    // `--help` and `--version` are `src/main.zig`'s own. The rule that an
    // option is not a command name has to let them through, which is what
    // `own_words` is for.
    //
    // Mutation check: drop that list and `chock --help` opens an interface, or
    // is refused by `run`'s parser as an unknown option.
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
    // **The whole line and nothing else.** This asserted only that the output
    // held "chock", which the versionless `chock (prototype)` passed just as
    // well, so it could not tell a build that reports its number from one that
    // does not. `main.version_line` is pinned against `build.zig.zon` off the
    // disk by a test in that file, so this compares the binary against the
    // manifest.
    //
    // Mutation check: print `version` without the `chock ` in front of it, or
    // add a second line to the answer, and this fails.
    try testing.expectEqualStrings(version_line ++ "\n", versioned.out);
    try testing.expectEqualStrings("", versioned.err);
    try testing.expectEqual(@as(u8, 0), versioned.code);

    // And a word that is not an option is still read as a command name.
    var missing = try runChock(gpa, io, &box.env, &.{"nonesuch"});
    defer missing.deinit(gpa);
    try testing.expect(std.mem.indexOf(u8, missing.err, "there is no command named") != null);
}

/// `haystack` holds `needle`.
fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) return;
    return sayWhatItSaid(haystack, needle);
}

/// `haystack` holds no `needle`.
fn expectMissing(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) return;
    return sayWhatItSaid(haystack, needle);
}

/// Fail, and carry both the text that was looked for and the report the
/// command really printed into what a person reads.
///
/// **The report is the evidence.** Every test here reads a stream a real
/// process wrote, and a bare `expect` on `indexOf` says only that a byte
/// string was there or was not. A failure then needs the run reproduced
/// before anybody knows what the command said, and a run under load may not
/// say the same thing twice. `expectEqualStrings` prints both sides, so the
/// report is in the failure. `test/plugin/engine.zig` carries the same pair
/// for the same reason, and neither file may write to standard error: see
/// `test/proto/lock.zig` for what a run step that does costs in a build log.
fn sayWhatItSaid(haystack: []const u8, needle: []const u8) !void {
    try testing.expectEqualStrings(needle, haystack);
    // Reached only when the two are equal, which `expectMissing` can still be
    // here with: the stream held the text and nothing else. The caller has
    // already decided that is a failure.
    return error.TestUnexpectedResult;
}

/// What the report says when a first run cannot work here. Spelled out rather
/// than imported: this file spawns a built binary and holds nothing of that
/// binary's own source.
const doctor_refusal = "a session cannot start here";

/// The heading over the rows that are true of the machine whatever the sandbox
/// driver does with it.
const doctor_first_run_heading = "Before a first run";

/// The heading over the layer rows, which a build whose driver applies no
/// layer never prints.
const doctor_layers_heading = "Sandbox layers";

/// Every layer row name the report prints on this host, in the order it prints
/// them.
///
/// **The names differ by platform because the mechanisms differ.** A user
/// namespace, Landlock and seccomp are Linux calls, and no macOS release has
/// any of them. The Seatbelt driver names its own layers instead, and names
/// each Linux mechanism it has no answer for. So one shared list would say a
/// Mac is broken for being a Mac.
///
/// **The list is written out rather than read from `src/doctor.zig`.** This
/// file starts the built binary and reads its bytes, and a test that imported
/// the same constant the program prints would agree with itself forever. See
/// the top comment for why nothing here is a unit test.
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

/// Layer names that appear in the report only as a layer row, for the half of
/// the test that reads a report with no layer rows at all.
///
/// **A short list on purpose.** `doctor_layer_names` holds ordinary words such
/// as `network` and `tool call`, and those turn up in the sentences of other
/// rows, so an absence test on the whole list could fail for a row that is not
/// a layer. Each name here names one mechanism and nothing else.
const doctor_absent_layer_names: []const []const u8 = switch (builtin.os.tag) {
    .macos => &.{ "seatbelt", "rlimit floor", "signal reach" },
    else => &.{ "landlock", "seccomp", "write^execute" },
};

test "chock doctor refuses a machine that cannot run a session, with a code a script can read" {
    // **This is the command's whole reason to exist**, and only a real process
    // can measure it: the report is built from `fork`, `unshare`, `mount` and
    // a real credential lookup, none of which a unit test in `src/doctor.zig`
    // can reach. The box below has no configuration in it, so no session can
    // be started from it whatever the kernel gives.
    //
    // Mutation check: return `Exit.finished` for a blocked verdict and the
    // code assertions fail. Return `Exit.usage` instead and the second one
    // fails, which is the confusion a script would answer by printing help.
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
    // Never 0, and never 1. `usage` already means the command line was wrong.
    try testing.expect(run.code != 0);
    try testing.expect(run.code != 1);

    // **The build is the first line, on a run nobody asked for detail on.**
    // This is the output a person pastes into a bug, and only a real process
    // can say the version reached standard output rather than the verbose
    // stream: a unit test in `src/doctor.zig` sets both streams itself.
    //
    // Mutation check: move the line in `printReport` to `tty.detail` and this
    // fails with the layers heading first.
    try testing.expectEqualStrings(version_line, std.mem.sliceTo(run.out, '\n'));

    // The rows are the answer somebody asked for, so they are on standard
    // output even when the verdict is a refusal. A `chock doctor > report.txt`
    // that answered "cannot start" with an empty file would be useless.
    try expectContains(run.out, doctor_first_run_heading);
    try expectContains(run.out, "credential");
    try expectContains(run.out, "workspace space");

    // The one line that says the machine cannot run a session is a diagnostic.
    try expectContains(run.err, doctor_refusal);
    try expectMissing(run.out, doctor_refusal);

    // Readable with no colour: a pipe gets no escape byte at all, so every
    // fact in the report survives as plain text.
    try testing.expect(std.mem.indexOfScalar(u8, run.out, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, run.err, 0x1b) == null);

    // And the state of a row is legible without colour: the word beside the
    // glyph says which of the four states it is.
    const counted = std.mem.count(u8, run.out, "BLOCKED");
    try testing.expect(counted >= 1);

    // **The column and the footer answer the same question, so they agree.**
    // Read on a Mac on 2026-08-25: two rows said `BLOCKED` and the footer said
    // one row stops a first run, and a report that argues with itself teaches
    // a person to trust neither half. The word appears in no sentence of the
    // report, so counting it counts the column. A unit test in
    // `src/doctor.zig` states its rows; this one counts what a real machine
    // really printed.
    //
    // Mutation check: answer the word from the row state alone and the two
    // numbers part on any machine with a layer it may not use.
    const marker = "Rows that stop a first run: ";
    const at = std.mem.indexOf(u8, run.err, marker).? + marker.len;
    const footer = try std.fmt.parseInt(usize, std.mem.sliceTo(run.err[at..], ' '), 10);
    try testing.expectEqual(footer, counted);
}

test "chock doctor prints a column of layers or the one sentence about the driver, never both" {
    // A build whose sandbox driver applies no layer refuses outright, and a
    // column of `NONE` rows would read as a machine that is nearly ready and
    // needs a setting changed. That is a different fact and it gets a
    // different sentence. **Stated as one rule rather than two platforms**, so
    // this measures what the built binary does rather than what this test
    // believes about the host.
    //
    // Mutation check: print the layer rows on a driver that gives nothing and
    // both halves below are true at once, which fails.
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
        // Every layer the header of a running session names is named here too,
        // before one starts, and each one is measured rather than assumed.
        for (doctor_layer_names) |name| {
            try expectContains(run.out, name);
        }
    } else {
        // The sentence names the call that refuses and says the gap is
        // permanent, so nobody spends an afternoon looking for a setting.
        try expectContains(run.err, "Sandbox.spawn refuses");
        try expectContains(run.err, "permanent");
        // And no layer row at all, which is the point of the sentence. The
        // names are this host's own, because a Linux name on a Mac would be
        // absent whatever the report said and would prove nothing.
        for (doctor_absent_layer_names) |name| {
            try expectMissing(run.out, name);
        }
    }
}

test "chock doctor leaves nothing of its own behind" {
    // The layer probes mount a capped tmpfs and an overlay, which needs real
    // directories on a real filesystem. **A directory somebody finds a month
    // later under their own session directory is a directory nobody can
    // explain**, so this asserts the tree is gone.
    //
    // Mutation check: drop the chmod in `removeProbeRoot` and the overlay's
    // own `work/work`, which the kernel makes with mode 0, stops `deleteTree`
    // halfway and this fails.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{ "doctor", "--project", box.root });
    defer run.deinit(gpa);

    // Asked of the program rather than worked out here, the same way
    // `sessionDirOf` does: a second copy of `session.projectKey` would agree
    // with itself forever and stop agreeing with the program.
    const session_dir = try sessionDirOf(gpa, io, &box);
    defer gpa.free(session_dir);

    // **A scan and not one built name.** The probe tree carries the running
    // process's id, so this test cannot name it, and it must not: a name built
    // here would go on agreeing with itself after the program stopped using
    // it. The session directory belongs to this test's own project, so
    // anything under it with that prefix was left by the run above and by
    // nothing else.
    var opened = try std.Io.Dir.openDirAbsolute(io, session_dir, .{ .iterate = true });
    defer opened.close(io);
    var it = opened.iterate();
    while (try it.next(io)) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "doctor.probe")) continue;
        // The name is the evidence: a bare `expect` would say a probe was left
        // without saying which, and the name is what tells a reader whether
        // the tree or the drop file survived.
        try testing.expectEqualStrings("", entry.name);
    }
}
