//! The program `test/workspace/darwin_escape.zig` drives. It rebuilds a real
//! `Sandbox.Config` from the blobs on its command line, calls
//! `chock_sandbox.spawn` with it, and reports what the kernel answered.
//!
//! **A separate program, because `spawn` forks.** `fork` carries only the
//! calling thread into the child, so its caller must be single threaded, and
//! the zig test runner is not. This is the same shape
//! `test/sandbox/darwin_probe.zig` and `test/workspace/escape_probe.zig` both
//! use, and for the same reason.
//!
//! **Nothing here inspects a Seatbelt profile.** Every answer this program
//! gives comes from a real `open` or a real `execve` inside a profile the
//! kernel applied. A test that read the profile text would pass against a
//! profile that denies nothing at all.
//!
//! Command line, for the outer invocation:
//!   darwin-probe <op> <cwd> <mounts-blob> <rules-blob> <env-blob> <args-blob>
//!
//! `<op>` is one of:
//!   write    spawn this same program again, inside the sandbox, with
//!            "spawned-write" and the one path `<args-blob>` holds. The inner
//!            invocation builds no sandbox of its own, so whatever it meets is
//!            the doing of the profile alone.
//!   run      spawn the argv `<args-blob>` holds, inside the sandbox, in
//!            `<cwd>`. Used for the real git commands.
//!   spawned-write   create `<args-blob>` for write. The inner half of "write",
//!            and never invoked from the outside.
//!
//! `<mounts-blob>` is zero or more lines, one per mount, fields separated by
//! 0x01, the first field always the kind:
//!   "bind\x01<source>\x01<target>\x01<read_only, 0 or 1>"
//!   "deny\x01<target>"
//! `<rules-blob>` is one line per Landlock rule, "<path>\x01<access bits>".
//! `<env-blob>` is one line per variable, each a complete "KEY=VALUE".
//! `<args-blob>` is one line per argv element. Lines are separated by "\n" and
//! an empty blob is the empty string.
//!
//! Exit codes:
//!   0 - the operation succeeded.
//!   1 - the operation was refused by the kernel.
//!   2 - the command line is wrong, or the operation is not one this program
//!       knows.
//!   3 - this program could not build the config it was given, before any
//!       sandbox was asked for. Never reused by 0 or 1: a setup failure that
//!       answers the code a passing test asserts has shipped twice in this
//!       project.
//!   5 - the operation failed for a reason the design does not predict.
//!  21 - `spawn` failed for a reason not named below.
//!  24 - `sandbox_init` refused the profile, so no boundary was ever built.
//!  25 - the config named a path this platform cannot put where it was asked.
//!  26 - the profile could not be built at all.
//!
//! **21 and up did not use to exist, and every one of them answered 3.** So a
//! build log could not tell a machine that refused to nest a Seatbelt profile
//! from a blob this program failed to parse. The numbers match
//! `test/sandbox/darwin_probe.zig`, so one vocabulary reads across both logs.

const std = @import("std");
const sandbox = @import("chock-sandbox");

const succeeded: u8 = 0;
const refused: u8 = 1;
const bad_arguments: u8 = 2;
const setup_failed: u8 = 3;
const wrong_failure: u8 = 5;
const spawn_refused: u8 = 21;
const profile_refused: u8 = 24;
const not_expressible: u8 = 25;
const profile_unbuildable: u8 = 26;

/// What one `spawn` failure exits with. **One code per cause**, because
/// `setup_failed` used to cover both a refused profile and a blob this program
/// could not read, and those two ask opposite things of whoever reads the log.
/// Measured on a real Mac on 2026-08-26: inside a `nix build`, where the
/// builder already holds a Seatbelt profile, `spawn` answers
/// `LandlockRestrictFailed`, which is `profile_refused`.
fn exitFor(err: anyerror) u8 {
    return switch (err) {
        error.LandlockRestrictFailed => profile_refused,
        error.NoMountNamespace => not_expressible,
        error.LandlockInitFailed => profile_unbuildable,
        else => spawn_refused,
    };
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const arguments = try init.args.toSlice(allocator);
    if (arguments.len < 2) return bad_arguments;

    const self_path = arguments[0];
    const operation = arguments[1];

    if (std.mem.eql(u8, operation, "spawned-write")) {
        if (arguments.len != 3) return bad_arguments;
        return createForWrite(arguments[2]);
    }

    if (arguments.len != 7) return bad_arguments;
    const cwd = arguments[2];
    const mounts = parseMounts(allocator, arguments[3]) catch return setup_failed;
    const rules = parseRules(allocator, arguments[4]) catch return setup_failed;
    const env = parseLines(allocator, arguments[5]) catch return setup_failed;
    const args = parseLines(allocator, arguments[6]) catch return setup_failed;

    var inner: []const []const u8 = args;
    if (std.mem.eql(u8, operation, "write")) {
        if (args.len != 1) return bad_arguments;
        var built: std.ArrayList([]const u8) = .empty;
        built.append(allocator, self_path) catch return setup_failed;
        built.append(allocator, "spawned-write") catch return setup_failed;
        built.append(allocator, args[0]) catch return setup_failed;
        inner = built.items;
    } else if (!std.mem.eql(u8, operation, "run")) {
        return bad_arguments;
    }

    const term = sandbox.spawn(allocator, .{
        .root = "/",
        .mounts = mounts,
        .rules = rules,
        .cwd = cwd,
        .env = env,
    }, inner, null, null) catch |err| return exitFor(err);

    return switch (term) {
        .exited => |code| switch (code) {
            0 => succeeded,
            refused => refused,
            bad_arguments => bad_arguments,
            else => wrong_failure,
        },
        else => wrong_failure,
    };
}

/// Create `path` for write, and report what the kernel said. **The inner half
/// of "write", and the only place this program touches the probed path.**
fn createForWrite(path: []const u8) u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len >= buffer.len) return bad_arguments;
    @memcpy(buffer[0..path.len], path);
    buffer[path.len] = 0;
    const zero_terminated: [*:0]const u8 = @ptrCast(&buffer);

    const handle = std.c.open(zero_terminated, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o644));
    if (handle < 0) {
        return switch (std.posix.errno(handle)) {
            .PERM, .ACCES, .ROFS => refused,
            else => wrong_failure,
        };
    }
    defer _ = std.c.close(handle);
    const written = std.c.write(handle, "chock finding 4\n", 16);
    if (written != 16) return wrong_failure;
    return succeeded;
}

fn parseLines(allocator: std.mem.Allocator, blob: []const u8) ![]const []const u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    if (blob.len == 0) return lines.toOwnedSlice(allocator);
    var parts = std.mem.splitScalar(u8, blob, '\n');
    while (parts.next()) |line| {
        if (line.len == 0) continue;
        try lines.append(allocator, line);
    }
    return lines.toOwnedSlice(allocator);
}

fn parseMounts(allocator: std.mem.Allocator, blob: []const u8) ![]const sandbox.namespace.Mount {
    var mounts: std.ArrayList(sandbox.namespace.Mount) = .empty;
    const lines = try parseLines(allocator, blob);
    for (lines) |line| {
        var fields = std.mem.splitScalar(u8, line, 0x01);
        const kind = fields.next() orelse return error.BadMount;
        if (std.mem.eql(u8, kind, "bind")) {
            const source = fields.next() orelse return error.BadMount;
            const target = fields.next() orelse return error.BadMount;
            const read_only = fields.next() orelse return error.BadMount;
            try mounts.append(allocator, .{ .bind = .{
                .source = source,
                .target = target,
                .read_only = std.mem.eql(u8, read_only, "1"),
            } });
        } else if (std.mem.eql(u8, kind, "deny")) {
            const target = fields.next() orelse return error.BadMount;
            try mounts.append(allocator, .{ .deny = .{ .target = target } });
        } else {
            return error.BadMount;
        }
    }
    return mounts.toOwnedSlice(allocator);
}

fn parseRules(allocator: std.mem.Allocator, blob: []const u8) ![]const sandbox.Config.Rule {
    var rules: std.ArrayList(sandbox.Config.Rule) = .empty;
    const lines = try parseLines(allocator, blob);
    for (lines) |line| {
        var fields = std.mem.splitScalar(u8, line, 0x01);
        const path = fields.next() orelse return error.BadRule;
        const bits = fields.next() orelse return error.BadRule;
        try rules.append(allocator, .{
            .path = path,
            .access = @bitCast(try std.fmt.parseInt(u64, bits, 10)),
        });
    }
    return rules.toOwnedSlice(allocator);
}
