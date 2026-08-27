//! Reads the environment a project's Nix dev shell states.
//!
//! The easy answer is wrong: `nix print-dev-env --json` does not run
//! `shellHook`, and many
//! flakes do real setup in it, so the environment has to come from a shell
//! that sourced the dev environment and then ran the hook. That is what
//! nix-direnv does, and it is what `read` below does.
//!
//! ## The statement is the difference between two shells
//!
//! **A dev shell's own statement cannot be read off one environment**, and
//! the reason is measurable rather than theoretical: a developer who uses
//! direnv already has the dev shell loaded when they type `chock run`, so
//! "everything the sourcing shell ended up with" is the same list whether or
//! not the sourcing happened, and "everything that changed" is empty. Both
//! naive rules give an answer that depends on where the user started the
//! program, which is not a property of the project at all.
//!
//! So `read` runs the same `bash` twice, from the same small base
//! environment, and the dev shell is **the difference**: one run sources the
//! dev environment and evaluates `shellHook`, the other does nothing. What
//! the two have in common is `bash` and the base; what only the first one
//! has is the project's. Nothing about the caller's own environment can
//! change the result, and the result is therefore the same on a direnv
//! machine and a bare one.
//!
//! **The base is deliberately small**, `base_keys` below, and it is
//! subtracted again by the same rule, so none of it reaches the sandbox. The
//! host's own environment is not passed through: an agent that could read
//! `ANTHROPIC_API_KEY` or `AWS_SECRET_ACCESS_KEY` out of a tool call's
//! environment would be a worse leak than the one this milestone closes.
//!
//! ## The shell is the script's own, never the host's
//!
//! **A stock macOS has bash 3.2 at `/bin/bash`, and bash 3.2 cannot read
//! what `nix print-dev-env` writes.** Measured on macOS 24.6 on 2026-08-25
//! against this project's own flake: the dump carries the nixpkgs setup
//! functions, one of which uses the bash 4 `;&` of a `case`, and `/bin/bash`
//! stops at `syntax error near unexpected token ';&'` on line 2029. A person
//! whose `PATH` happens to lead with a nix bash never sees it. A person who
//! installed nix and left their `PATH` alone lost the whole dev shell, and
//! a measurement on the same machine showed what that costs: no `zig` on the
//! host `PATH` at all, and a `/usr/bin/cc` that answers "No developer tools
//! were found".
//!
//! A version check that refuses would name the fault and still leave the
//! person with no toolchain. **The script names the bash that wrote it**, and
//! anybody who has nix has that bash on disk, so `bashFor` reads the name out
//! of the script and runs that. See `interpreter_names`.
//!
//! `nix print-dev-env` itself, in `printDevEnv`, is the one command here
//! that does get the user's whole environment. It has to: it reads
//! `~/.config/nix/nix.conf`, the flake registry, and the daemon settings,
//! and a `nix` that cannot see those behaves differently from the
//! `nix develop` the same user runs by hand. Its output is a bash script and
//! not an environment, so nothing of the host's leaks through it.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const proc = @import("proc.zig");

pub const Error = proc.Error || error{
    /// `nix print-dev-env` failed. Its own standard error travels with a
    /// `Diagnostic`, when the caller asked for one: a readable evaluation
    /// error is the goal, and until that parser exists the raw trace is far
    /// more useful than an error name.
    EvalFailed,
    /// The shell that sourced the dev environment failed, which means the
    /// script `nix` wrote could not be read by the `bash` on this host.
    DevEnvFailed,
};

/// The host variables the two shells start from, and why each one is here.
/// Every one of them is subtracted again afterwards, so this list decides
/// what a `shellHook` can *see*, never what a tool call receives.
///
/// **Short on purpose.** A hook that needs more than this is asking for the
/// user's session, and the answer to that is the same as everywhere else in
/// Chock: name what you need.
const base_keys = [_][]const u8{
    // A hook that writes a cache, a `.direnv`, or a lock file needs to know
    // where the user's home is. Unset, bash falls back to the passwd entry
    // for some things and simply fails for `~`.
    "HOME",
    // A hook that prints a message, or runs a program that colours its
    // output, reads one of these two. `USER` also appears in ordinary
    // project scripts.
    "USER",
    "LOGNAME",
    // A hook that draws anything reads `TERM`, and a program that finds it
    // unset can decide it is on a terminal that cannot even move a cursor.
    "TERM",
};

/// The largest dev environment script this reads. `nix print-dev-env` for a
/// plain `mkShell` is about seventy kilobytes; a large flake with many
/// build inputs is a few hundred. A megabyte is far past any of that and
/// still bounds a `nix` that has gone wrong.
const max_script_bytes: usize = 4 * 1024 * 1024;

/// The largest environment dump this reads. An environment is a few
/// kilobytes. This bounds a `shellHook` that exports something enormous.
const max_env_bytes: usize = 1024 * 1024;

/// The names a dev environment script can hold its own interpreter under, in
/// the order they are trusted. The first one the script names, and the store
/// still holds, is the bash `read` runs.
///
/// * `BASH` is bash's own record of the program that is running. In this
///   script it is the bash that wrote the dump, so it can read it back.
/// * `CONFIG_SHELL` is what nixpkgs tells a build script to run when the
///   script needs a bash rather than a `/bin/sh`. It is that bash.
/// * `SHELL` is what stdenv states, and it is the shell `nix develop` gives
///   a person who runs it by hand.
/// * `builder` is the derivation's own builder. **`nix develop` refuses a
///   derivation whose builder is not a bash**, so a script that exists at
///   all names a bash here.
///
/// A script that names none of them is read by the host's bash, which is
/// what every version of this did.
const interpreter_names = [_][]const u8{ "BASH", "CONFIG_SHELL", "SHELL", "builder" };

/// Run `nix print-dev-env <flake_dir>` and return the script it wrote. The
/// caller owns the result.
///
/// The flake reference is the directory itself, exactly what a user would
/// type to `nix develop`, so a project in a git work tree is read the same
/// way `nix develop` reads it and a user who sees an error here can
/// reproduce it by hand with one command.
pub fn printDevEnv(
    allocator: std.mem.Allocator,
    io: std.Io,
    nix_program: []const u8,
    flake_dir: []const u8,
    host_env: *const std.process.Environ.Map,
    diag: ?diagnostic.Sink,
) Error![]u8 {
    var output = try proc.run(allocator, io, .{
        .argv = &.{ nix_program, "print-dev-env", flake_dir },
        .env = host_env,
        .cwd = flake_dir,
        .max_output_bytes = max_script_bytes,
        .diag = diag,
    });
    errdefer output.deinit(allocator);

    if (!output.succeeded()) {
        // Copied before the return, because `errdefer` above is what frees
        // the bytes the diagnostic keeps. The copy goes into the sink's own
        // allocator, which is not `allocator` here: see `DevShell.load`.
        try diagnostic.noteRefusal(diag, .nix_print_dev_env, output.stderr);
        return error.EvalFailed;
    }

    allocator.free(output.stderr);
    return output.stdout;
}

/// The bash that can read `script`: the one the script names, when that one
/// is still on disk, and the host's own otherwise. The caller owns the
/// result.
///
/// The fall back to the host is not a silent one. A host bash that cannot
/// parse the script fails in `read`, which answers `DevEnvFailed` and puts
/// what bash said in the diagnostic.
pub fn bashFor(
    allocator: std.mem.Allocator,
    io: std.Io,
    script: []const u8,
    host_env: *const std.process.Environ.Map,
) Error![]u8 {
    if (bashIn(script)) |named| {
        if (isProgram(io, named)) return allocator.dupe(u8, named);
    }
    return proc.resolve(allocator, io, host_env, "bash");
}

/// The interpreter `script` names, or null. A slice of `script`.
fn bashIn(script: []const u8) ?[]const u8 {
    for (interpreter_names) |name| {
        const value = quotedValue(script, name) orelse continue;
        if (std.fs.path.isAbsolute(value)) return value;
    }
    return null;
}

/// The value of the line `name='value'`, when the script has one.
///
/// `nix print-dev-env` writes one variable to a line in that form, and
/// escapes a quote inside the value as `'\''`. A value holding a quote is
/// therefore not one line and is not a program path either, so this reads
/// only the simple form and skips anything else. The lines that follow, the
/// `export name` ones, do not start with `name=` and are skipped by the same
/// rule.
fn quotedValue(script: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, script, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, name)) continue;
        const rest = line[name.len..];
        if (rest.len < 3 or !std.mem.startsWith(u8, rest, "='") or rest[rest.len - 1] != '\'') continue;
        const value = rest[2 .. rest.len - 1];
        if (std.mem.indexOfScalar(u8, value, '\'') != null) continue;
        return value;
    }
    return null;
}

/// True when `path` names something that can be run. A directory is refused
/// for the reason `proc.resolve` refuses one: it is a path `execve` can never
/// start.
fn isProgram(io: std.Io, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind != .directory;
}

/// Everything `read` needs to run its two shells. Absolute program paths,
/// never bare names: see `lib/chock-nix/proc.zig`'s own top comment.
pub const Params = struct {
    /// The `bash` that sources the dev environment. **From `bashFor` and not
    /// from the host's `PATH`**: see this file's own top comment.
    bash_program: []const u8,
    /// The `env` that prints the result. A program and not a shell builtin
    /// because `compgen -e`, the only builtin that lists exported names, is
    /// not available in a non-interactive `bash` at all: measured, it
    /// answers "compgen: command not found".
    env_program: []const u8,
    /// The file holding what `printDevEnv` returned.
    script_path: []const u8,
    /// Where the two shells run. The project root, so a `shellHook` that
    /// reads a file of the project finds it.
    cwd: []const u8,
    /// Where `base_keys` are read from.
    host_env: *const std.process.Environ.Map,
    /// Where a fault past what `Error` can say is left, and who owns what it
    /// points at. A field of the params and not a parameter, for the reason
    /// `proc.Options` gives, and a `Sink` for the reason it gives too.
    diag: ?diagnostic.Sink = null,
};

/// The variables the dev shell states, as `KEY=VALUE`, sorted by name. The
/// caller owns the slice and every string in it.
///
/// Sorted so that the cache file of two runs of the same dev shell is the
/// same bytes, which is what makes a cache comparable and a test readable.
pub fn read(allocator: std.mem.Allocator, io: std.Io, params: Params) Error![][]u8 {
    var base_env = std.process.Environ.Map.init(allocator);
    defer base_env.deinit();
    for (base_keys) |key| {
        if (params.host_env.get(key)) |value| try base_env.put(key, value);
    }

    // The two shells differ in one thing: whether they source the dev
    // environment first. Everything else about them, the flags, the base
    // environment, the working directory, and the program that prints the
    // result, is identical, because whatever they share is subtracted.
    const sourcing_script =
        \\source "$1" || exit 3
        \\eval "$shellHook"
        \\unset shellHook
        \\exec "$2" -0
    ;
    const bare_script =
        \\exec "$2" -0
    ;

    const sourced = try dumpEnvironment(allocator, io, params, &base_env, sourcing_script);
    defer allocator.free(sourced);
    const bare = try dumpEnvironment(allocator, io, params, &base_env, bare_script);
    defer allocator.free(bare);

    return subtract(allocator, bare, sourced);
}

/// Run one of `read`'s two shells and return its raw `env -0` output.
fn dumpEnvironment(
    allocator: std.mem.Allocator,
    io: std.Io,
    params: Params,
    base_env: *const std.process.Environ.Map,
    script: []const u8,
) Error![]u8 {
    var output = try proc.run(allocator, io, .{
        .argv = &.{
            params.bash_program,
            "--noprofile",
            "--norc",
            "-c",
            script,
            // `$0`, which only ever shows up in an error message from bash
            // itself. Named so that message says which program produced it.
            "chock-dev-shell",
            params.script_path,
            params.env_program,
        },
        .env = base_env,
        .cwd = params.cwd,
        .max_output_bytes = max_env_bytes,
        .diag = params.diag,
    });
    errdefer output.deinit(allocator);

    if (!output.succeeded()) {
        try diagnostic.noteRefusal(params.diag, .dev_env_shell, output.stderr);
        return error.DevEnvFailed;
    }

    allocator.free(output.stderr);
    return output.stdout;
}

/// The records of `sourced` that `bare` does not already have, by name and
/// by value: see this file's own top comment. The caller owns the result and
/// every string in it.
fn subtract(allocator: std.mem.Allocator, bare: []const u8, sourced: []const u8) Error![][]u8 {
    var base: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer base.deinit(allocator);

    var bare_records = std.mem.splitScalar(u8, bare, 0);
    while (bare_records.next()) |record| {
        const split = splitRecord(record) orelse continue;
        try base.put(allocator, split.key, split.value);
    }

    var kept: std.ArrayList([]u8) = .empty;
    errdefer {
        for (kept.items) |item| allocator.free(item);
        kept.deinit(allocator);
    }

    var sourced_records = std.mem.splitScalar(u8, sourced, 0);
    while (sourced_records.next()) |record| {
        const split = splitRecord(record) orelse continue;
        if (base.get(split.key)) |had| {
            if (std.mem.eql(u8, had, split.value)) continue;
        }
        try kept.append(allocator, try allocator.dupe(u8, record));
    }

    const result = try kept.toOwnedSlice(allocator);
    std.mem.sort([]u8, result, {}, lessThanRecord);
    return result;
}

const Record = struct { key: []const u8, value: []const u8 };

/// One `KEY=VALUE` record, or null for anything that is not one. A record
/// with no `=`, or one whose name is empty, is not an environment variable
/// and never becomes one: this is `env`'s output being read as data, and
/// data is checked before it is used.
fn splitRecord(record: []const u8) ?Record {
    const equals = std.mem.indexOfScalar(u8, record, '=') orelse return null;
    if (equals == 0) return null;
    return .{ .key = record[0..equals], .value = record[equals + 1 ..] };
}

fn lessThanRecord(_: void, a: []u8, b: []u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// Every test here runs a real `bash` against a dev environment script the
// test wrote itself. That is the mechanism `read` actually uses, minus the
// one command a test cannot depend on: `nix`. A script written by hand and a
// script written by `nix print-dev-env` are both a file that bash sources,
// so what is proven here is what happens in a session.

const TestShell = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    dir_path: []u8,
    bash: []u8,
    env_program: []u8,
    host_env: std.process.Environ.Map,

    fn init(allocator: std.mem.Allocator) !TestShell {
        var host_env = try std.testing.environ.createMap(allocator);
        errdefer host_env.deinit();

        const bash = try proc.resolve(allocator, std.testing.io, &host_env, "bash");
        errdefer allocator.free(bash);
        const env_program = try proc.resolve(allocator, std.testing.io, &host_env, "env");
        errdefer allocator.free(env_program);

        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(std.testing.io, &buffer);
        const dir_path = try allocator.dupe(u8, buffer[0..len]);

        return .{
            .allocator = allocator,
            .tmp = tmp,
            .dir_path = dir_path,
            .bash = bash,
            .env_program = env_program,
            .host_env = host_env,
        };
    }

    fn deinit(self: *TestShell) void {
        self.allocator.free(self.dir_path);
        self.allocator.free(self.bash);
        self.allocator.free(self.env_program);
        self.host_env.deinit();
        self.tmp.cleanup();
        self.* = undefined;
    }

    /// Write `text` as the dev environment script and read what it states.
    ///
    /// The bash comes from `bashFor` and not from `self.bash`, so every test
    /// below goes through the choice a session makes.
    fn readScript(self: *TestShell, text: []const u8) Error![][]u8 {
        var file = self.tmp.dir.createFile(std.testing.io, "dev-env.sh", .{}) catch return error.Unexpected;
        file.writeStreamingAll(std.testing.io, text) catch return error.Unexpected;
        file.close(std.testing.io);

        const script_path = std.fmt.allocPrint(
            self.allocator,
            "{s}/dev-env.sh",
            .{self.dir_path},
        ) catch return error.OutOfMemory;
        defer self.allocator.free(script_path);

        const bash = try bashFor(self.allocator, std.testing.io, text, &self.host_env);
        defer self.allocator.free(bash);

        return read(self.allocator, std.testing.io, .{
            .bash_program = bash,
            .env_program = self.env_program,
            .script_path = script_path,
            .cwd = self.dir_path,
            .host_env = &self.host_env,
        });
    }
};

fn freeRecords(allocator: std.mem.Allocator, records: [][]u8) void {
    for (records) |record| allocator.free(record);
    allocator.free(records);
}

fn valueOf(records: [][]u8, key: []const u8) ?[]const u8 {
    for (records) |record| {
        const split = splitRecord(record) orelse continue;
        if (std.mem.eql(u8, split.key, key)) return split.value;
    }
    return null;
}

test "a variable the dev environment exports is part of the answer" {
    const allocator = std.testing.allocator;
    var shell = TestShell.init(allocator) catch |err| switch (err) {
        error.ProgramNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer shell.deinit();

    const records = try shell.readScript("export CHOCK_TEST_TOOL=/nix/store/aaa-tool\n");
    defer freeRecords(allocator, records);

    try std.testing.expectEqualStrings("/nix/store/aaa-tool", valueOf(records, "CHOCK_TEST_TOOL").?);
}

test "shellHook runs, and what it exports is part of the answer" {
    const allocator = std.testing.allocator;
    var shell = TestShell.init(allocator) catch |err| switch (err) {
        error.ProgramNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer shell.deinit();

    // The whole reason `--json` is refused: this variable exists only because
    // something ran the hook.
    const records = try shell.readScript(
        \\export CHOCK_TEST_DECLARED=declared
        \\shellHook='export CHOCK_TEST_HOOKED=hooked'
        \\
    );
    defer freeRecords(allocator, records);

    try std.testing.expectEqualStrings("declared", valueOf(records, "CHOCK_TEST_DECLARED").?);
    try std.testing.expectEqualStrings("hooked", valueOf(records, "CHOCK_TEST_HOOKED").?);
}

test "the hook's own text is not carried into the answer" {
    const allocator = std.testing.allocator;
    var shell = TestShell.init(allocator) catch |err| switch (err) {
        error.ProgramNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer shell.deinit();

    // `nix print-dev-env` exports `shellHook` itself, and it can be
    // kilobytes of shell script. It has already run by the time the
    // environment is read, so carrying it would put a copy of the hook in
    // every tool call's environment for nothing.
    const records = try shell.readScript(
        \\export shellHook='export CHOCK_TEST_HOOKED=hooked'
        \\
    );
    defer freeRecords(allocator, records);

    try std.testing.expectEqual(@as(?[]const u8, null), valueOf(records, "shellHook"));
    try std.testing.expectEqualStrings("hooked", valueOf(records, "CHOCK_TEST_HOOKED").?);
}

test "nothing the shell and the base already had reaches the answer" {
    const allocator = std.testing.allocator;
    var shell = TestShell.init(allocator) catch |err| switch (err) {
        error.ProgramNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer shell.deinit();

    // A dev environment that states one variable states exactly one
    // variable. `HOME` is in the base and the script does not touch it;
    // `PWD` and `SHLVL` are bash's own. A tool call has never had the
    // user's environment and does not start now.
    const records = try shell.readScript("export CHOCK_TEST_ONLY=one\n");
    defer freeRecords(allocator, records);

    try std.testing.expectEqual(@as(?[]const u8, null), valueOf(records, "HOME"));
    try std.testing.expectEqual(@as(?[]const u8, null), valueOf(records, "PWD"));
    try std.testing.expectEqual(@as(?[]const u8, null), valueOf(records, "SHLVL"));
    try std.testing.expectEqual(@as(?[]const u8, null), valueOf(records, "_"));
    try std.testing.expectEqual(@as(usize, 1), records.len);
}

test "a variable the dev environment changes is part of the answer even when the base has it" {
    const allocator = std.testing.allocator;
    var shell = TestShell.init(allocator) catch |err| switch (err) {
        error.ProgramNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer shell.deinit();

    // The `PATH` case, in miniature: a name the base carries and the dev
    // shell replaces belongs to the dev shell. Subtracting by name alone
    // would drop it, and a tool call would then resolve its programs
    // against the wrong toolchain.
    const records = try shell.readScript("export HOME=/nix/store/aaa-fake-home\n");
    defer freeRecords(allocator, records);

    try std.testing.expectEqualStrings("/nix/store/aaa-fake-home", valueOf(records, "HOME").?);
}

test "a dev environment that cannot be sourced is a failure, not an empty answer" {
    const allocator = std.testing.allocator;
    var shell = TestShell.init(allocator) catch |err| switch (err) {
        error.ProgramNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer shell.deinit();

    // A script bash refuses to parse. Reading this as "the dev shell states
    // nothing" would silently give the session the fallback toolchain and
    // never say so.
    try std.testing.expectError(error.DevEnvFailed, shell.readScript("this is ( not shell\n"));
}

test "the script's own bash is the one that reads it" {
    const allocator = std.testing.allocator;
    var shell = TestShell.init(allocator) catch |err| switch (err) {
        error.ProgramNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer shell.deinit();

    // A stand in for nix's bash: it leaves a mark and then runs the host's,
    // so the answer stays the answer and the mark proves which program ran.
    // Only a real program will do here. A test that checked the string
    // `bashFor` returned would pass even if `read` went on using the host's.
    const wrapper_path = try std.fmt.allocPrint(allocator, "{s}/nix-bash", .{shell.dir_path});
    defer allocator.free(wrapper_path);
    const mark_path = try std.fmt.allocPrint(allocator, "{s}/ran", .{shell.dir_path});
    defer allocator.free(mark_path);
    {
        var file = try shell.tmp.dir.createFile(std.testing.io, "nix-bash", .{
            .permissions = .fromMode(0o755),
        });
        defer file.close(std.testing.io);
        const text = try std.fmt.allocPrint(
            allocator,
            "#!/bin/sh\necho ran >> {s}\nexec {s} \"$@\"\n",
            .{ mark_path, shell.bash },
        );
        defer allocator.free(text);
        try file.writeStreamingAll(std.testing.io, text);
    }

    const script = try std.fmt.allocPrint(
        allocator,
        "BASH='{s}'\nexport CHOCK_TEST_ONLY=one\n",
        .{wrapper_path},
    );
    defer allocator.free(script);

    const records = try shell.readScript(script);
    defer freeRecords(allocator, records);
    try std.testing.expectEqualStrings("one", valueOf(records, "CHOCK_TEST_ONLY").?);

    // Both shells, the sourcing one and the bare one, so the difference is
    // still a difference of the same program.
    const marks = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, mark_path, allocator, .limited(64));
    defer allocator.free(marks);
    try std.testing.expectEqualStrings("ran\nran\n", marks);
}

test "a bash the script names but the store no longer holds falls back to the host's" {
    const allocator = std.testing.allocator;

    var host_env = try std.testing.environ.createMap(allocator);
    defer host_env.deinit();
    const host_bash = proc.resolve(allocator, std.testing.io, &host_env, "bash") catch
        return error.SkipZigTest;
    defer allocator.free(host_bash);

    // The `nix-collect-garbage` case. Refusing here would break a machine
    // that works today, and the host bash still gets its chance to fail out
    // loud in `read`.
    const chosen = try bashFor(
        allocator,
        std.testing.io,
        "BASH='/nix/store/00000000000000000000000000000000-bash-5.3/bin/bash'\n",
        &host_env,
    );
    defer allocator.free(chosen);
    try std.testing.expectEqualStrings(host_bash, chosen);
}

test "the interpreter is read from the first name the script really states" {
    // The head of a real script, in miniature. `BASH` here is the shape the
    // first lines of `nix print-dev-env` have, `PATH=${PATH:-}`, which
    // states no path at all. The `export` lines are not assignments.
    const in_order =
        \\BASH=${BASH:-}
        \\CONFIG_SHELL='/nix/store/aaaa-bash-5.3/bin/bash'
        \\export CONFIG_SHELL
        \\SHELL='/nix/store/bbbb-bash-5.3/bin/bash'
        \\export SHELL
        \\
    ;
    try std.testing.expectEqualStrings("/nix/store/aaaa-bash-5.3/bin/bash", bashIn(in_order).?);

    // And `BASH` is preferred to both, because it is the one bash wrote
    // about itself rather than one a flake could have set.
    const with_bash = "BASH='/nix/store/cccc-bash-5.3/bin/bash'\n" ++ in_order;
    try std.testing.expectEqualStrings("/nix/store/cccc-bash-5.3/bin/bash", bashIn(with_bash).?);

    // A relative name is not a program path this can run, and a script that
    // states nothing usable states nothing.
    try std.testing.expectEqual(@as(?[]const u8, null), bashIn("BASH='bash'\n"));
    try std.testing.expectEqual(@as(?[]const u8, null), bashIn("export PATH=/usr/bin\n"));
}

test "a record with no name and a record with no value are read the way env means them" {
    try std.testing.expectEqual(@as(?Record, null), splitRecord("no-equals-here"));
    try std.testing.expectEqual(@as(?Record, null), splitRecord("=orphan-value"));
    const empty = splitRecord("EMPTY=").?;
    try std.testing.expectEqualStrings("EMPTY", empty.key);
    try std.testing.expectEqualStrings("", empty.value);
}
