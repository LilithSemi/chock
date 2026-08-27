//! Runs one operation inside a real `Sandbox.spawn` sandbox, built from a
//! `Sandbox.Config` that `test/workspace/escape.zig` serializes from a real
//! `Workspace.sandboxConfig`. This is the same "outer process builds a config,
//! then execs a probe" shape `test/sandbox/probe.zig` and
//! `test/workspace/overlay_helper.zig` both use, for the same reason:
//! `Sandbox.spawn` calls `fork`, and `fork` only carries the calling thread
//! into the child, so its caller must be single threaded. The zig test runner
//! that runs `escape.zig`'s own tests is not that caller. This program is.
//!
//! Nothing in this file touches `std.Io`: see `overlay_helper.zig`'s own top
//! comment for why. Every path comes in through argv, already resolved by
//! `escape.zig`, which does use `std.Io`, safely, because it never calls
//! `Sandbox.spawn` itself.
//!
//! Command line, for the outer invocation:
//!   escape-probe <op> <root> <cwd> <mounts-blob> <rules-blob> <env-blob> <target-or-git-path>
//!
//! `<op>` is one of:
//!   write             try to create <target-or-git-path> for write, inside the sandbox
//!   delete            try to unlink <target-or-git-path>, inside the sandbox
//!   read              read <target-or-git-path> whole, inside the sandbox, and report
//!                     whether the bytes are the project's own or the deny notice.
//!                     Used by `test/workspace/escape.zig` for the
//!                     deny_read block: the file must not be readable, and the
//!                     model must be told rather than shown an empty file.
//!   connect           try to open a TCP connection to <target-or-git-path>, which is
//!                     "<dotted quad>:<port>", from inside the sandbox. Used by
//!                     `test/broker/actions.zig` to prove that an approval the broker
//!                     acted on gave the sandbox no route to the very address the
//!                     broker itself just read.
//!   git-status        bind <target-or-git-path> (git's own absolute host path) into
//!                     the sandbox and run "git status" with it
//!   git-commit        bind <target-or-git-path> (git's own absolute host path) into
//!                     the sandbox and run "git add", "git commit", "git cat-file -e"
//!                     against the pre-existing parent commit, "git log", and "git
//!                     show" with it, each its own Sandbox.spawn call, in order. Every
//!                     one of them must succeed.
//!   git-alternate-tamper   same shape as git-commit, except GIT_ALTERNATE_OBJECT_DIRECTORIES
//!                     is replaced with a bogus path before every spawn. The commit must
//!                     still succeed and the cat-file read of the pre-existing parent
//!                     commit must now fail: see this program's own top comment on the
//!                     security question a renamed alternate asks.
//!   git-push          <target-or-git-path> is "<git's own absolute host path>\x01<url>".
//!                     Runs the real git twice inside the sandbox, by its absolute path,
//!                     with no shim anywhere: "git --version", which must exit 0, and
//!                     then "git push <url> HEAD", which must not. Used by
//!                     `test/broker/git_shim.zig`: the shim
//!                     prevents a mistake and does not prevent an attack, so an agent
//!                     that names the real binary directly is not stopped by it, and the
//!                     capability layers are what stop the push.
//!
//! `<mounts-blob>` is zero or more lines, one per mount, fields separated by
//! 0x01, the first field always the kind:
//!   "bind\x01<source>\x01<target>\x01<read_only, 0 or 1>"
//!   "overlay\x01<lower>\x01<upper>\x01<work>\x01<target>"
//!   "proc\x01<target>"
//!   "deny\x01<target>"
//! `<rules-blob>` is the same shape for Landlock rules, each
//!   "<path>\x01<access bits, decimal>"
//! `<env-blob>` is zero or more lines, one per environment variable, each
//! already a complete "KEY=VALUE" string with no field separator needed.
//! Lines are separated by "\n". An empty blob is the empty string.
//!
//! This program always adds two mounts of its own to whatever the blobs
//! carry: `/nix/store`, read only, so the dynamic linker can resolve the
//! shared libraries of whichever binary it execs next, and the binary it is
//! about to exec itself (its own binary for "write" and "delete", or the git
//! binary named on the command line for "git-status"), bound at a fixed
//! in-sandbox path and made executable.
//!
//! "write" and "delete" exec this same binary again, inside the sandbox, with
//! a "spawned-write" or "spawned-delete" operation and the one target path:
//! that inner invocation does no setup of its own, the same "spawned-"
//! convention `test/sandbox/probe.zig` uses, so whatever it hits is entirely
//! the doing of `Sandbox.spawn`'s own `applyLayers`, not of a filter or a
//! mount tree this program built for itself.
//!
//! Exit codes:
//!   0 - the operation succeeded, or (git-status) exited 0, or (git-commit)
//!       every step in the flow exited 0, or (git-alternate-tamper) the add
//!       and the commit exited 0 and the tampered read of the pre-existing
//!       parent commit failed, exactly as predicted.
//!   1 - the operation was refused with the specific errno the design
//!       predicts: EROFS for "write", EBUSY for "delete", ENETUNREACH for
//!       "connect". For "read", the file held exactly
//!       `namespace.deny_notice`, which is the denial holding and the model
//!       being told why.
//!   2 - the arguments on the command line are wrong, or the operation is
//!       not one this program knows.
//!   3 - the sandbox setup itself failed, or spawning it did, before the
//!       probed operation ever ran. Never reused by 0 or 1: a setup failure
//!       that returns the code a passing test asserts has shipped twice in
//!       this project, and a reviewer caught it both times.
//!   4 - (read only) the file read as empty. Its own code, and not folded
//!       into 0 or 1, because an empty file is the outcome the deny design
//!       refuses to give: an agent that reads an empty `.env` concludes the
//!       project has no configuration and acts on that. A test asserting 1
//!       therefore fails loudly, with a code that says which mistake was
//!       made, if a later change binds an empty file instead of the notice.
//!   5 - the operation failed, but not for the reason the design predicts:
//!       for git-commit, any step of the flow that did not exit 0; for
//!       git-alternate-tamper, the add or the commit failing, or, worse, the
//!       tampered read of the pre-existing parent commit succeeding anyway;
//!       for git-push, "git --version" failing, which means the push's own
//!       failure would say nothing, since git could not run at all.
//!  63 - this machine would not give the sandbox its namespaces, so nothing
//!       this operation is about was measured. **Not a pass and not a
//!       failure**: the caller skips and says why. See
//!       `namespace.nothing_measured_exit_status`.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("chock-sandbox");

/// Where this program binds its own binary inside the sandbox, for "write"
/// and "delete".
const self_target = "/probe";
/// Where this program binds the git binary inside the sandbox, for
/// "git-status", "git-commit", and "git-alternate-tamper".
const git_target = "/probe-git";

/// The name of the file the git-commit and git-alternate-tamper flows add
/// and commit, inside the worktree. `escape.zig` writes this file into the
/// worktree's own checkout, on the host, before it ever starts this probe,
/// with content that was never committed before: a repeat of content that
/// already has a blob object in the real store would let git skip writing a
/// new object at all, since git never writes an object it can already find,
/// which would prove nothing about the scratch store this flow exists to
/// exercise.
const commit_test_file = "chock-object-store-test.txt";

/// End this program with `nothing_measured_exit_status`, and say why, when
/// `err` is the sandbox refusing to be built at all.
///
/// **A boundary that was never reached is not a boundary that held.** Every
/// operation in this program asks whether a workspace mount stops something,
/// and every one of them needs a sandbox to ask inside. A machine that will
/// not give one measures nothing, and the caller must skip on it rather than
/// count it. Returns for every other error, so a real setup fault keeps the
/// exit code that says so.
///
/// **Nothing is printed, on purpose.** `build.zig`'s own `failOnTestStderr`
/// fails the build when a test binary writes to standard error, and a caller
/// that lets this program inherit its own descriptors would carry these bytes
/// there. The exit status is the whole answer.
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

    // The inner exec targets. No setup of their own: see this file's own top
    // comment on the "spawned-" convention. Reached only as the exec target
    // of a real Sandbox.spawn call further down in this same function.
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
        // Neither of these two config paths exists inside the sandbox.
        // Pointing git's own config lookup at them is the same effect as
        // /dev/null: a git config file that is simply not there is read as
        // empty, not as an error.
        env = &.{
            "GIT_CONFIG_GLOBAL=/nonexistent-chock-global-gitconfig",
            "GIT_CONFIG_SYSTEM=/nonexistent-chock-system-gitconfig",
            "GIT_TERMINAL_PROMPT=0",
            "HOME=/nonexistent-chock-home",
        };
    } else if (std.mem.eql(u8, op, "git-push")) {
        // "<git path>\x01<url>", the same 0x01 field separator every blob on
        // this command line already uses.
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

/// Add the two mounts and rules every git invocation in this program needs
/// beyond the caller's own blobs: the git binary itself, bound at
/// `git_target` and made executable, and `/dev/null`, which git opens
/// directly (confirmed by hand: without this, a git command fails with
/// "could not open '/dev/null' for reading and writing"). Chock's own
/// default `/dev` does not exist yet, so this binds the host's own
/// `/dev/null` in.
///
/// The `/dev/null` mount is not read only: `namespace.zig`'s own
/// `markReadOnly` also sets `NODEV` on a read only mount, which then
/// refuses to open the device node at all, `EPERM`, confirmed by hand.
/// Nothing about `/dev/null` needs write protection in the first place: it
/// is a bit bucket, not a path that must stay unwritable. Its rule is not
/// `AccessFs.read_write` either: that set carries directory only rights
/// such as `read_dir` and `make_dir`, and Landlock refuses to add a rule
/// that carries one of those for a path that is not a directory, `EINVAL`,
/// confirmed by hand. `/dev/null` is a character device file, so it gets
/// exactly the two rights it needs: open for read, open for write.
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

/// Build the environment for the git-commit and git-alternate-tamper flows:
/// `passed_env`, the exact `GIT_OBJECT_DIRECTORY` and
/// `GIT_ALTERNATE_OBJECT_DIRECTORIES` values a real `Workspace.sandboxConfig`
/// built, plus the same config-neutralizing variables the git-status branch
/// already needs, so a global or system gitconfig on the host running this
/// test can never change what git decides to do.
///
/// When `bogus_alternate` is true, `GIT_ALTERNATE_OBJECT_DIRECTORIES` from
/// `passed_env` is dropped and replaced with a path nothing mounts. This is
/// the security question a renamed alternate asks, made concrete rather
/// than argued: `runGitCommitFlow` proves what naming a
/// different alternate actually gets an agent.
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

/// Run one git subcommand as its own `Sandbox.spawn` call, sharing `mounts`,
/// `rules`, `env`, and `root` with every other step of the same flow. Each
/// spawn rebuilds its own mount tree under the same `root`; that is safe,
/// because a mount lives in the ephemeral mount namespace the exiting child
/// already tore down when that spawn finished, and `buildRoot` tolerates a
/// target directory that is already there from the step before it.
///
/// Returns `null` on a sandbox setup failure, which the caller reports as
/// exit code 3, the same as every other setup failure in this program.
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

/// Run the real git by its absolute path inside the sandbox, with no shim in
/// front of it, and try to push to `url`.
///
/// The shim prevents a mistake and it does not prevent an attack, and this
/// is the honest half of that sentence made
/// concrete: naming the real binary directly skips the shim entirely, which
/// is easy, and the push still does not happen, because the sandbox has no
/// route out for it to use.
///
/// `git --version` runs first so that the push's failure means something. A
/// git that could not start at all would also exit nonzero, and that would
/// prove nothing about the network.
///
/// Returns 0 when the push succeeded, which is the sandbox leaking; 1 when
/// it failed, which is what the design predicts; 5 when git could not run.
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

/// Run the git-commit or git-alternate-tamper flow: `git add` and `git
/// commit`, always with `env`, the real environment a caller's own
/// `Workspace.sandboxConfig` built. Both must succeed, whether or not
/// `tampered_env` is present: neither one ever needs to read the alternate
/// to write a new object, only `GIT_OBJECT_DIRECTORY`, which `env` already
/// points at the scratch store, so tampering with the alternate on a
/// separate command later can never change whether these two succeed.
///
/// Then `git cat-file -e HEAD~1^{commit}` tests whether the pre-existing
/// parent commit, the one the project already had before this session ever
/// started, can still be read. `tampered_env`, when present, is used only
/// for this one step, in place of `env`: this is the security question a
/// renamed alternate asks, made concrete. `tampered_env` is
/// `null` for plain git-commit, which continues on to `git log` and `git
/// show`, proving both can read the commit the sandbox itself just wrote.
///
/// Returns 0 when every step behaves as `tampered_env` predicts:
///
/// - `null` (git-commit): every step must succeed. The scratch object
///   store's own three claims, proven together: `git add` and `git commit` work
///   against a read only object store, the alternate can read history
///   older than the session, and `git log` and `git show` can read the
///   commit the sandbox itself just wrote.
/// - present (git-alternate-tamper): `git add` and `git commit` must still
///   succeed, but the read of the pre-existing parent commit, run with
///   `tampered_env` instead of `env`, must now fail, since that one
///   command's own `GIT_ALTERNATE_OBJECT_DIRECTORIES` no longer names a
///   real path. An agent that renames its own alternate on a command of its
///   own breaks only that command's own ability to read history it did not
///   just write; it reaches nothing that lands a change in the project's
///   real repository, and nothing that touches the real object store's
///   write side at all, which stays refused by the mount layer regardless
///   of what any variable names.
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
        // add and commit already succeeded above, with the real,
        // untampered env, and the tampered read just failed as predicted:
        // the attack is contained.
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

/// Try to create `target` for write. 0 on success, 1 when the kernel refuses
/// with EROFS, the exact errno a read only bind mount gives, 5 for any other
/// refusal.
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

/// Read `target` whole and say what was in it. See this file's own top
/// comment for the four codes and why an empty file has one of its own.
///
/// **The comparison is against the exact notice string, and the string comes
/// from `chock-sandbox` itself.** A copy of those words written here would
/// keep on matching after somebody changed the real one, and the test would go
/// on passing while a model started reading something else.
fn spawnedRead(target: []const u8) u8 {
    const target_z = std.heap.page_allocator.dupeZ(u8, target) catch return 5;
    defer std.heap.page_allocator.free(target_z);

    const fd_rc = linux.open(target_z.ptr, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return 5;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    // Larger than the notice and larger than anything a test writes, so a
    // short read is a fact about the file and never about this buffer.
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

/// Try to unlink `target`. 0 on success, 1 when the kernel refuses with
/// EBUSY, the exact errno a file that is itself a mount point gives, 5 for
/// any other refusal.
fn spawnedDelete(target: []const u8) u8 {
    const target_z = std.heap.page_allocator.dupeZ(u8, target) catch return 5;
    defer std.heap.page_allocator.free(target_z);
    const unlink_errno = linux.errno(linux.unlink(target_z.ptr));
    if (unlink_errno == .SUCCESS) return 0;
    return if (unlink_errno == .BUSY) 1 else 5;
}

/// Try to open a TCP connection to `address`, written as
/// "<dotted quad>:<port>". 0 when the connection is made, which means the
/// sandbox reached the network; 1 when the kernel refuses with ENETUNREACH,
/// the exact errno a network namespace with no route and a loopback that is
/// down gives; 5 for any other refusal, including a refusal that came from
/// the far end rather than from the namespace.
///
/// ENETUNREACH and not ECONNREFUSED is the whole point. A refusal by the far
/// end would mean the packet left the sandbox. This one never leaves.
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

/// Turn the Term of the sandboxed process into this program's own exit
/// status. A signal is re-raised, so a caller watching this program's own
/// Term sees the same signal the sandboxed process died from.
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

/// Read the path of this running binary through /proc/self/exe. Used to bind
/// this same program into the sandbox it is about to build, so the "write"
/// and "delete" operations have something to re-exec.
/// `std.fs.selfExePathAlloc` does not exist in this Zig version, so the link
/// is read directly, the same way `test/sandbox/probe.zig` does it.
fn selfExePath(arena: std.mem.Allocator) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.readlink("/proc/self/exe", &buffer, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    return arena.dupe(u8, buffer[0..rc]);
}

const ParseError = error{ OutOfMemory, BadBlob };

/// Parse a mounts blob, documented at this file's own top comment, into a
/// list. Every field this returns is a slice straight into `blob`, never
/// copied: `blob` itself is a slice of `arena`-owned argv memory, so it
/// outlives every use this program makes of the result.
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

/// Same shape as `parseMounts`, for a rules blob.
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

/// Parse an env blob, documented at this file's own top comment, into a
/// slice of already-complete "KEY=VALUE" strings, one per line. Every entry
/// is a slice straight into `blob`, the same convention `parseMounts` and
/// `parseRules` use, for the same reason.
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
