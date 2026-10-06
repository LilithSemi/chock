//! Reads the environment a project's Nix dev shell states.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const proc = @import("proc.zig");

pub const Error = proc.Error || error{
    EvalFailed,
    DevEnvFailed,
};

const base_keys = [_][]const u8{
    "HOME",
    "USER",
    "LOGNAME",
    "TERM",
};

const max_script_bytes: usize = 4 * 1024 * 1024;

const max_env_bytes: usize = 1024 * 1024;

const interpreter_names = [_][]const u8{ "BASH", "CONFIG_SHELL", "SHELL", "builder" };

pub fn printDevEnv(
    allocator: std.mem.Allocator,
    io: std.Io,
    nix_program: []const u8,
    flake_dir: []const u8,
    shell_name: ?[]const u8,
    host_env: *const std.process.Environ.Map,
    diag: ?diagnostic.Sink,
) Error![]u8 {
    const installable = if (shell_name) |name|
        try std.fmt.allocPrint(allocator, "{s}#{s}", .{ flake_dir, name })
    else
        flake_dir;
    defer if (shell_name != null) allocator.free(installable);

    var output = try proc.run(allocator, io, .{
        .argv = &.{ nix_program, "print-dev-env", installable },
        .env = host_env,
        .cwd = flake_dir,
        .max_output_bytes = max_script_bytes,
        .diag = diag,
    });
    errdefer output.deinit(allocator);

    if (!output.succeeded()) {
        // Copied before the return, because the errdefer above frees the bytes the diagnostic keeps. The copy goes into the sink's own allocator, not this function's.
        try diagnostic.noteRefusal(diag, .nix_print_dev_env, output.stderr);
        return error.EvalFailed;
    }

    allocator.free(output.stderr);
    return output.stdout;
}

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

fn bashIn(script: []const u8) ?[]const u8 {
    for (interpreter_names) |name| {
        const value = quotedValue(script, name) orelse continue;
        if (std.fs.path.isAbsolute(value)) return value;
    }
    return null;
}

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

fn isProgram(io: std.Io, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind != .directory;
}

pub const Params = struct {
    bash_program: []const u8,
    env_program: []const u8,
    script_path: []const u8,
    cwd: []const u8,
    host_env: *const std.process.Environ.Map,
    staging_dir: ?[]const u8 = null,
    diag: ?diagnostic.Sink = null,
};

pub fn read(allocator: std.mem.Allocator, io: std.Io, params: Params) Error![][]u8 {
    var base_env = std.process.Environ.Map.init(allocator);
    defer base_env.deinit();
    for (base_keys) |key| {
        if (params.host_env.get(key)) |value| try base_env.put(key, value);
    }
    if (params.staging_dir) |dir| try base_env.put("TMPDIR", dir);

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

fn splitRecord(record: []const u8) ?Record {
    const equals = std.mem.indexOfScalar(u8, record, '=') orelse return null;
    if (equals == 0) return null;
    return .{ .key = record[0..equals], .value = record[equals + 1 ..] };
}

fn lessThanRecord(_: void, a: []u8, b: []u8) bool {
    return std.mem.lessThan(u8, a, b);
}

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

    try std.testing.expectError(error.DevEnvFailed, shell.readScript("this is ( not shell\n"));
}

test "the script's own bash is the one that reads it" {
    const allocator = std.testing.allocator;
    var shell = TestShell.init(allocator) catch |err| switch (err) {
        error.ProgramNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer shell.deinit();

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
    const in_order =
        \\BASH=${BASH:-}
        \\CONFIG_SHELL='/nix/store/aaaa-bash-5.3/bin/bash'
        \\export CONFIG_SHELL
        \\SHELL='/nix/store/bbbb-bash-5.3/bin/bash'
        \\export SHELL
        \\
    ;
    try std.testing.expectEqualStrings("/nix/store/aaaa-bash-5.3/bin/bash", bashIn(in_order).?);

    const with_bash = "BASH='/nix/store/cccc-bash-5.3/bin/bash'\n" ++ in_order;
    try std.testing.expectEqualStrings("/nix/store/cccc-bash-5.3/bin/bash", bashIn(with_bash).?);

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
