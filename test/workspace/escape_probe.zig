//! Runs one operation inside a real `Sandbox.spawn` sandbox, built from a
//! config that `test/workspace/escape.zig` serializes. Its own process because
//! `Sandbox.spawn` calls `fork`, which carries only the calling thread into the
//! child, and the zig test runner is not a single threaded caller. Nothing here
//! touches `std.Io`: every path arrives through argv.
//!
//! Command line, for the outer invocation:
//!   escape-probe <op> <root> <cwd> <mounts-blob> <rules-blob> <env-blob> <target-or-git-path>
//!
//! `<op>` is one of:
//!   write             create <target-or-git-path> for write
//!   delete            unlink <target-or-git-path>
//!   read              read it whole, and report the project's own bytes or
//!                     the deny notice
//!   connect           open TCP to it, written "<dotted quad>:<port>"
//!   git-status        bind git at its host path and run "git status"
//!   git-commit        same bind, then "git add", "git commit", "git cat-file
//!                     -e" on the parent commit, "git log", "git show", each
//!                     its own spawn. Every one must succeed
//!   git-alternate-tamper   git-commit with GIT_ALTERNATE_OBJECT_DIRECTORIES
//!                     replaced by a bogus path. The commit must still succeed
//!                     and the cat-file read must now fail
//!   git-push          it is "<git host path>\x01<url>". Runs the real git with
//!                     no shim: "git --version", which must exit 0, then
//!                     "git push <url> HEAD", which must not
//!
//! `<mounts-blob>` is zero or more lines, one per mount, fields separated by
//! 0x01, the first field always the kind:
//!   "bind\x01<source>\x01<target>\x01<read_only, 0 or 1>"
//!   "overlay\x01<lower>\x01<upper>\x01<work>\x01<target>"
//!   "proc\x01<target>"
//!   "deny\x01<target>"
//! `<rules-blob>` is the same shape for Landlock rules, each
//!   "<path>\x01<access bits, decimal>"
//! `<env-blob>` is one complete "KEY=VALUE" string per line. Lines are
//! separated by "\n" and an empty blob is the empty string.
//!
//! This program always adds `/nix/store` read only, so the dynamic linker can
//! resolve shared libraries, and the binary it is about to exec.
//!
//! "write" and "delete" exec this same binary again inside the sandbox with a
//! "spawned-" operation, which does no setup of its own, so whatever it hits is
//! entirely the doing of `Sandbox.spawn`.
//!
//! Exit status:
//!   0   the operation succeeded, or every step of a git flow exited 0
//!   1   refused with the errno the design predicts: EROFS for "write", EBUSY
//!       for "delete", ENETUNREACH for "connect", and for "read" the file held
//!       exactly `namespace.deny_notice`
//!   2   the command line is wrong, or the operation is unknown
//!   3   the setup or the spawn failed before the operation ran. Never reused
//!       by 0 or 1: a setup failure returning a passing code has shipped twice
//!   4   (read only) the file read as empty. Its own code, because an agent
//!       that reads an empty `.env` concludes the project has no configuration
//!   5   the operation failed, but not for the reason the design predicts
//!  63   this machine would not give the sandbox its namespaces, so the
//!       operation never ran. Not a pass and not a failure: the caller skips

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("chock-sandbox");

const self_target = "/probe";
const git_target = "/probe-git";

/// git never writes an object it can already find, so `escape.zig` fills this
/// file with content that was never committed before.
const commit_test_file = "chock-object-store-test.txt";

/// Nothing is printed: `build.zig`'s `failOnTestStderr` fails the build on a
/// byte written to standard error.
fn endIfNothingMeasured(err: anyerror) void {
    if (err != error.NamespaceFailed) return;
    std.process.exit(sandbox.namespace.nothing_measured_exit_status);
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("usage: escape-probe <op> ...\n", .{});
        return 2;
    }
    const op = args[1];

    if (std.mem.eql(u8, op, "spawned-write")) {
        if (args.len != 3) return 2;
        return spawnedWrite(args[2]);
    }
    if (std.mem.eql(u8, op, "spawned-delete")) {
        if (args.len != 3) return 2;
        return spawnedDelete(args[2]);
    }
    if (std.mem.eql(u8, op, "spawned-connect")) {
        if (args.len != 3) return 2;
        return spawnedConnect(args[2]);
    }
    if (std.mem.eql(u8, op, "spawned-read")) {
        if (args.len != 3) return 2;
        return spawnedRead(args[2]);
    }

    if (args.len != 8) {
        std.debug.print(
            "usage: escape-probe <op> <root> <cwd> <mounts-blob> <rules-blob> <env-blob> <target-or-git-path>\n",
            .{},
        );
        return 2;
    }
    const root = args[2];
    const cwd = args[3];
    const mounts_blob = args[4];
    const rules_blob = args[5];
    const env_blob = args[6];
    const target_or_git = args[7];

    var mounts = parseMounts(arena, mounts_blob) catch {
        std.debug.print("parsing the mount list failed\n", .{});
        return 3;
    };
    var rules = parseRules(arena, rules_blob) catch {
        std.debug.print("parsing the rule list failed\n", .{});
        return 3;
    };
    const passed_env = parseEnvBlob(arena, env_blob) catch {
        std.debug.print("parsing the env list failed\n", .{});
        return 3;
    };

    mounts.append(arena, .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } }) catch return 3;
    rules.append(arena, .{ .path = "/nix/store", .access = sandbox.landlock.AccessFs.read_only }) catch return 3;

    var argv: []const []const u8 = undefined;
    var env: []const []const u8 = &.{};

    if (std.mem.eql(u8, op, "write") or std.mem.eql(u8, op, "delete") or
        std.mem.eql(u8, op, "connect") or std.mem.eql(u8, op, "read"))
    {
        const self_path = selfExePath(arena) catch |err| {
            std.debug.print("reading /proc/self/exe failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        mounts.append(arena, .{ .bind = .{ .source = self_path, .target = self_target, .read_only = true } }) catch return 3;
        rules.append(arena, .{ .path = self_target, .access = .{ .execute = true, .read_file = true } }) catch return 3;

        const spawned_op = if (std.mem.eql(u8, op, "write"))
            "spawned-write"
        else if (std.mem.eql(u8, op, "delete"))
            "spawned-delete"
        else if (std.mem.eql(u8, op, "read"))
            "spawned-read"
        else
            "spawned-connect";
        argv = arena.dupe([]const u8, &.{ self_target, spawned_op, target_or_git }) catch return 3;
    } else if (std.mem.eql(u8, op, "git-status")) {
        addGitRuntimeMounts(arena, &mounts, &rules, target_or_git) catch return 3;

        argv = arena.dupe([]const u8, &.{ git_target, "status" }) catch return 3;
        // Neither config path exists inside the sandbox. git reads a config
        // file that is not there as empty, not as an error.
        env = &.{
            "GIT_CONFIG_GLOBAL=/nonexistent-chock-global-gitconfig",
            "GIT_CONFIG_SYSTEM=/nonexistent-chock-system-gitconfig",
            "GIT_TERMINAL_PROMPT=0",
            "HOME=/nonexistent-chock-home",
        };
    } else if (std.mem.eql(u8, op, "git-push")) {
        const separator = std.mem.indexOfScalar(u8, target_or_git, 1) orelse {
            std.debug.print("git-push: expected <git path>\\x01<url>, got {s}\n", .{target_or_git});
            return 2;
        };
        const git_path = target_or_git[0..separator];
        const url = target_or_git[separator + 1 ..];

        addGitRuntimeMounts(arena, &mounts, &rules, git_path) catch return 3;
        const git_env = buildGitCommitEnv(arena, passed_env, false) catch return 3;
        return runGitPushFlow(arena, root, cwd, mounts.items, rules.items, git_env, url);
    } else if (std.mem.eql(u8, op, "git-commit") or std.mem.eql(u8, op, "git-alternate-tamper")) {
        addGitRuntimeMounts(arena, &mounts, &rules, target_or_git) catch return 3;
        const bogus_alternate = std.mem.eql(u8, op, "git-alternate-tamper");
        const git_env = buildGitCommitEnv(arena, passed_env, false) catch return 3;
        const tampered_env: ?[]const []const u8 = if (bogus_alternate)
            buildGitCommitEnv(arena, passed_env, true) catch return 3
        else
            null;
        return runGitCommitFlow(arena, root, cwd, mounts.items, rules.items, git_env, tampered_env);
    } else {
        std.debug.print("unknown operation: {s}\n", .{op});
        return 2;
    }

    const term = sandbox.spawn(arena, .{
        .root = root,
        .mounts = mounts.items,
        .rules = rules.items,
        .cwd = cwd,
        .env = env,
        .network = .none,
    }, argv, null, null) catch |err| {
        endIfNothingMeasured(err);
        std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
        return 3;
    };

    return reportTerm(term);
}

/// git opens `/dev/null` directly, and without it a git command fails with
/// "could not open '/dev/null' for reading and writing".
///
/// That mount is not read only, because `markReadOnly` also sets `NODEV`, which
/// then refuses to open the device node at all with `EPERM`. Its rule is not
/// `AccessFs.read_write` either: that set carries directory only rights, and
/// Landlock refuses those for a path that is not a directory with `EINVAL`.
fn addGitRuntimeMounts(
    arena: std.mem.Allocator,
    mounts: *std.ArrayList(sandbox.namespace.Mount),
    rules: *std.ArrayList(sandbox.Config.Rule),
    git_path: []const u8,
) std.mem.Allocator.Error!void {
    try mounts.append(arena, .{ .bind = .{ .source = git_path, .target = git_target, .read_only = true } });
    try rules.append(arena, .{ .path = git_target, .access = .{ .execute = true, .read_file = true } });
    try mounts.append(arena, .{ .bind = .{ .source = "/dev/null", .target = "/dev/null", .read_only = false } });
    try rules.append(arena, .{ .path = "/dev/null", .access = .{ .read_file = true, .write_file = true } });
}

fn buildGitCommitEnv(
    arena: std.mem.Allocator,
    passed_env: []const []const u8,
    bogus_alternate: bool,
) std.mem.Allocator.Error![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    for (passed_env) |entry| {
        if (bogus_alternate and std.mem.startsWith(u8, entry, "GIT_ALTERNATE_OBJECT_DIRECTORIES=")) continue;
        try list.append(arena, entry);
    }
    if (bogus_alternate) {
        try list.append(arena, "GIT_ALTERNATE_OBJECT_DIRECTORIES=/nonexistent-chock-alternate");
    }
    try list.append(arena, "GIT_CONFIG_GLOBAL=/nonexistent-chock-global-gitconfig");
    try list.append(arena, "GIT_CONFIG_SYSTEM=/nonexistent-chock-system-gitconfig");
    try list.append(arena, "GIT_TERMINAL_PROMPT=0");
    try list.append(arena, "HOME=/nonexistent-chock-home");
    return list.toOwnedSlice(arena);
}

/// Each spawn rebuilds its own mount tree under the same `root`. That is safe:
/// a mount lives in the mount namespace the exiting child already tore down,
/// and `buildRoot` accepts a target directory left from the step before.
fn runGitStep(
    arena: std.mem.Allocator,
    root: []const u8,
    cwd: []const u8,
    mounts: []const sandbox.namespace.Mount,
    rules: []const sandbox.Config.Rule,
    env: []const []const u8,
    argv_tail: []const []const u8,
) ?std.process.Child.Term {
    var argv: std.ArrayList([]const u8) = .empty;
    argv.append(arena, git_target) catch return null;
    argv.appendSlice(arena, argv_tail) catch return null;

    return sandbox.spawn(arena, .{
        .root = root,
        .mounts = mounts,
        .rules = rules,
        .cwd = cwd,
        .env = env,
        .network = .none,
    }, argv.items, null, null) catch |err| {
        endIfNothingMeasured(err);
        std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
        return null;
    };
}

/// Naming the real binary skips the shim, and the push still fails because the
/// sandbox has no route out. `git --version` runs first so the push's failure
/// means something: a git that could not start would also exit nonzero.
fn runGitPushFlow(
    arena: std.mem.Allocator,
    root: []const u8,
    cwd: []const u8,
    mounts: []const sandbox.namespace.Mount,
    rules: []const sandbox.Config.Rule,
    env: []const []const u8,
    url: []const u8,
) u8 {
    const version_term = runGitStep(arena, root, cwd, mounts, rules, env, &.{"--version"}) orelse return 3;
    if (!exitedZero(version_term)) {
        std.debug.print("git-push: git --version did not exit 0, so git itself cannot run here\n", .{});
        return 5;
    }

    const push_term = runGitStep(arena, root, cwd, mounts, rules, env, &.{ "push", url, "HEAD" }) orelse return 3;
    if (exitedZero(push_term)) {
        std.debug.print("git-push: the push exited 0, so the sandbox let it out\n", .{});
        return 0;
    }
    return 1;
}

fn exitedZero(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

/// The add and the commit must succeed either way: neither reads the alternate
/// to write a new object. `tampered_env` is used for the cat-file step alone,
/// and it shows that renaming an alternate loses that one command its history.
fn runGitCommitFlow(
    arena: std.mem.Allocator,
    root: []const u8,
    cwd: []const u8,
    mounts: []const sandbox.namespace.Mount,
    rules: []const sandbox.Config.Rule,
    env: []const []const u8,
    tampered_env: ?[]const []const u8,
) u8 {
    const add_term = runGitStep(arena, root, cwd, mounts, rules, env, &.{ "add", commit_test_file }) orelse return 3;
    if (!exitedZero(add_term)) {
        std.debug.print("git add did not exit 0\n", .{});
        return 5;
    }

    const commit_term = runGitStep(arena, root, cwd, mounts, rules, env, &.{ "commit", "-m", "chock object store test" }) orelse return 3;
    if (!exitedZero(commit_term)) {
        std.debug.print("git commit did not exit 0\n", .{});
        return 5;
    }

    const cat_file_env = tampered_env orelse env;
    const cat_file_term = runGitStep(arena, root, cwd, mounts, rules, cat_file_env, &.{ "cat-file", "-e", "HEAD~1^{commit}" }) orelse return 3;
    const cat_file_ok = exitedZero(cat_file_term);

    if (tampered_env != null) {
        if (cat_file_ok) {
            std.debug.print("cat-file read the pre-existing parent commit even with a bogus alternate\n", .{});
            return 5;
        }
        return 0;
    }

    if (!cat_file_ok) {
        std.debug.print("cat-file could not read the pre-existing parent commit through the alternate\n", .{});
        return 5;
    }

    const log_term = runGitStep(arena, root, cwd, mounts, rules, env, &.{ "log", "--oneline" }) orelse return 3;
    if (!exitedZero(log_term)) {
        std.debug.print("git log did not exit 0\n", .{});
        return 5;
    }

    const show_term = runGitStep(arena, root, cwd, mounts, rules, env, &.{ "show", "--stat", "HEAD" }) orelse return 3;
    if (!exitedZero(show_term)) {
        std.debug.print("git show did not exit 0\n", .{});
        return 5;
    }

    return 0;
}

/// EROFS is the exact errno a read only bind mount gives.
fn spawnedWrite(target: []const u8) u8 {
    const target_z = std.heap.page_allocator.dupeZ(u8, target) catch return 5;
    defer std.heap.page_allocator.free(target_z);
    const fd_rc = linux.open(target_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
    const open_errno = linux.errno(fd_rc);
    if (open_errno == .SUCCESS) {
        _ = linux.close(@intCast(fd_rc));
        return 0;
    }
    return if (open_errno == .ROFS) 1 else 5;
}

/// The notice string comes from `chock-sandbox` itself. A copy written here
/// would go on matching after somebody changed the real one.
fn spawnedRead(target: []const u8) u8 {
    const target_z = std.heap.page_allocator.dupeZ(u8, target) catch return 5;
    defer std.heap.page_allocator.free(target_z);

    const fd_rc = linux.open(target_z.ptr, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return 5;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    // Larger than the notice, so a short read is a fact about the file.
    var buffer: [4096]u8 = undefined;
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(fd, buffer[filled..].ptr, buffer.len - filled);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return 5,
        }
        if (rc == 0) break;
        filled += rc;
    }

    if (filled == 0) return 4;
    if (std.mem.eql(u8, buffer[0..filled], sandbox.namespace.deny_notice)) return 1;
    return 0;
}

/// EBUSY is the exact errno a file that is itself a mount point gives.
fn spawnedDelete(target: []const u8) u8 {
    const target_z = std.heap.page_allocator.dupeZ(u8, target) catch return 5;
    defer std.heap.page_allocator.free(target_z);
    const unlink_errno = linux.errno(linux.unlink(target_z.ptr));
    if (unlink_errno == .SUCCESS) return 0;
    return if (unlink_errno == .BUSY) 1 else 5;
}

/// ENETUNREACH is the errno a network namespace with no route and a loopback
/// that is down gives. ECONNREFUSED instead would mean the packet left.
fn spawnedConnect(address: []const u8) u8 {
    const colon = std.mem.lastIndexOfScalar(u8, address, ':') orelse {
        std.debug.print("spawned-connect: expected <dotted quad>:<port>, got {s}\n", .{address});
        return 2;
    };
    const port = std.fmt.parseInt(u16, address[colon + 1 ..], 10) catch return 2;

    var octets: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, address[0..colon], '.');
    for (&octets) |*octet| {
        const part = parts.next() orelse return 2;
        octet.* = std.fmt.parseInt(u8, part, 10) catch return 2;
    }
    if (parts.next() != null) return 2;

    const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    if (linux.errno(fd) != .SUCCESS) return 5;
    defer _ = linux.close(@intCast(fd));

    var addr = std.mem.zeroes(linux.sockaddr.in);
    addr.family = linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, port);
    addr.addr = std.mem.readInt(u32, &octets, .big);

    const rc = linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    const connect_errno = linux.errno(rc);
    if (connect_errno == .SUCCESS) return 0;
    if (connect_errno == .NETUNREACH) return 1;
    std.debug.print("spawned-connect: connect failed with {s}, not ENETUNREACH\n", .{@tagName(connect_errno)});
    return 5;
}

/// A signal is re-raised, so a caller sees what the sandboxed process died from.
fn reportTerm(term: std.process.Child.Term) u8 {
    switch (term) {
        .exited => |code| return code,
        .signal => |sig| {
            std.posix.raise(sig) catch |err| {
                std.debug.print("could not re-raise {s}: {s}\n", .{ @tagName(sig), @errorName(err) });
            };
            return 5;
        },
        else => return 5,
    }
}

/// `std.fs.selfExePathAlloc` does not exist in this Zig version.
fn selfExePath(arena: std.mem.Allocator) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.readlink("/proc/self/exe", &buffer, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    return arena.dupe(u8, buffer[0..rc]);
}

const ParseError = error{ OutOfMemory, BadBlob };

/// Every field is a slice into `blob`, which is arena owned argv memory.
fn parseMounts(arena: std.mem.Allocator, blob: []const u8) ParseError!std.ArrayList(sandbox.namespace.Mount) {
    var list: std.ArrayList(sandbox.namespace.Mount) = .empty;
    if (blob.len == 0) return list;

    var lines = std.mem.splitScalar(u8, blob, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, 0x01);
        const kind = fields.next() orelse return error.BadBlob;
        if (std.mem.eql(u8, kind, "bind")) {
            const source = fields.next() orelse return error.BadBlob;
            const target = fields.next() orelse return error.BadBlob;
            const read_only_field = fields.next() orelse return error.BadBlob;
            try list.append(arena, .{ .bind = .{
                .source = source,
                .target = target,
                .read_only = std.mem.eql(u8, read_only_field, "1"),
            } });
        } else if (std.mem.eql(u8, kind, "overlay")) {
            const lower = fields.next() orelse return error.BadBlob;
            const upper = fields.next() orelse return error.BadBlob;
            const work = fields.next() orelse return error.BadBlob;
            const target = fields.next() orelse return error.BadBlob;
            try list.append(arena, .{ .overlay = .{
                .lower = lower,
                .upper = upper,
                .work = work,
                .target = target,
            } });
        } else if (std.mem.eql(u8, kind, "proc")) {
            const target = fields.next() orelse return error.BadBlob;
            try list.append(arena, .{ .proc = .{ .target = target } });
        } else if (std.mem.eql(u8, kind, "deny")) {
            const target = fields.next() orelse return error.BadBlob;
            try list.append(arena, .{ .deny = .{ .target = target } });
        } else {
            return error.BadBlob;
        }
    }
    return list;
}

fn parseRules(arena: std.mem.Allocator, blob: []const u8) ParseError!std.ArrayList(sandbox.Config.Rule) {
    var list: std.ArrayList(sandbox.Config.Rule) = .empty;
    if (blob.len == 0) return list;

    var lines = std.mem.splitScalar(u8, blob, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, 0x01);
        const path = fields.next() orelse return error.BadBlob;
        const bits_field = fields.next() orelse return error.BadBlob;
        const bits = std.fmt.parseInt(u64, bits_field, 10) catch return error.BadBlob;
        try list.append(arena, .{ .path = path, .access = @bitCast(bits) });
    }
    return list;
}

fn parseEnvBlob(arena: std.mem.Allocator, blob: []const u8) ParseError![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    if (blob.len == 0) return list.toOwnedSlice(arena);

    var lines = std.mem.splitScalar(u8, blob, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try list.append(arena, line);
    }
    return list.toOwnedSlice(arena);
}
