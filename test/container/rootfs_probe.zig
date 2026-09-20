//! Runs one program inside a real `Sandbox.spawn` sandbox whose whole root
//! filesystem is a container image that `chock-container` extracted. No
//! container runtime takes part.
//!
//! A separate program because `Sandbox.spawn` calls `fork`, so its caller must
//! be single threaded and the Zig test runner is not. Nothing here writes to
//! standard error, so every answer travels as an exit status.
//!
//! Command line:
//!   rootfs-probe <root> <cwd> <mounts-blob> <env-blob> <program> [args...]
//!
//! `<root>` is an empty directory that becomes the sandbox root.
//! `<mounts-blob>` is zero or more lines, one per mount, fields separated by
//! 0x01: `<source>\x01<target>\x01<kind, d or f>`.
//! `<env-blob>` is zero or more `KEY=VALUE` lines.
//!
//! Exit status:
//!   0 to 255 minus the four below   what the sandboxed program exited with
//!   251                             the command line was wrong
//!   252                             this program ran out of memory or could
//!                                   not parse a blob
//!   253                             `Sandbox.spawn` refused
//!    63                             this machine would not give the sandbox its
//!                                   namespaces, so the caller skips. See
//!                                   `namespace.nothing_measured_exit_status`.
//!   254                             the sandboxed program was signalled

const std = @import("std");
const sandbox = @import("chock-sandbox");

const bad_usage = 251;
const probe_fault = 252;
const spawn_refused = 253;
const program_signalled = 254;

const field = '\x01';

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.args.toSlice(arena);
    if (args.len < 6) return bad_usage;

    const root = args[1];
    const cwd = args[2];
    const mounts_blob = args[3];
    const env_blob = args[4];
    const argv = args[5..];

    var mounts: std.ArrayList(sandbox.namespace.Mount) = .empty;
    var rules: std.ArrayList(sandbox.Config.Rule) = .empty;

    parseMounts(arena, mounts_blob, &mounts, &rules) catch return probe_fault;

    // An image carries no `/proc`, and every real toolchain reads one.
    mounts.append(arena, .{ .proc = .{} }) catch return probe_fault;
    rules.append(arena, .{ .path = "/proc", .access = sandbox.landlock.AccessFs.read_only }) catch
        return probe_fault;

    // `std.tar` writes no device nodes, so an exported image holds an empty
    // ordinary file where `/dev/null` was. Not read only: `markReadOnly` also
    // sets `NODEV`, which then refuses to open the device node at all.
    mounts.append(arena, .{ .bind = .{
        .source = "/dev/null",
        .target = "/dev/null",
        .read_only = false,
    } }) catch return probe_fault;
    rules.append(arena, .{
        .path = "/dev/null",
        .access = .{ .read_file = true, .write_file = true },
    }) catch return probe_fault;

    const env = parseEnv(arena, env_blob) catch return probe_fault;

    const term = sandbox.spawn(arena, .{
        .root = root,
        .mounts = mounts.items,
        .rules = rules.items,
        .cwd = cwd,
        .env = env,
        .network = .none,
    }, argv, null, null) catch |err| {
        // A sandbox that cannot be built says nothing about the image.
        if (err == error.NamespaceFailed) return sandbox.namespace.nothing_measured_exit_status;
        return spawn_refused;
    };

    return switch (term) {
        .exited => |code| code,
        else => program_signalled,
    };
}

fn parseMounts(
    arena: std.mem.Allocator,
    blob: []const u8,
    mounts: *std.ArrayList(sandbox.namespace.Mount),
    rules: *std.ArrayList(sandbox.Config.Rule),
) !void {
    var lines = std.mem.splitScalar(u8, blob, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        var fields = std.mem.splitScalar(u8, line, field);
        const source = fields.next() orelse return error.BadBlob;
        const target = fields.next() orelse return error.BadBlob;
        const kind = fields.next() orelse return error.BadBlob;
        if (kind.len != 1) return error.BadBlob;

        try mounts.append(arena, .{ .bind = .{
            .source = source,
            .target = target,
            .read_only = true,
        } });

        // The kernel returns `EINVAL` for a directory rule over a regular file,
        // so the mount's own kind picks the rule.
        try rules.append(arena, .{
            .path = target,
            .access = switch (kind[0]) {
                'd' => sandbox.landlock.AccessFs.read_only,
                'f' => sandbox.landlock.AccessFs.read_only_file,
                else => return error.BadBlob,
            },
        });
    }
}

fn parseEnv(arena: std.mem.Allocator, blob: []const u8) ![]const []const u8 {
    var records: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, blob, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try records.append(arena, line);
    }
    return records.toOwnedSlice(arena);
}
