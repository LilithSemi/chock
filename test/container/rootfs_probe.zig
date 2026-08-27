//! Runs one program inside a real `Sandbox.spawn` sandbox, whose whole root
//! filesystem is a container image that `chock-container` extracted.
//!
//! **This is the acceptance test for the central design decision.**
//! `lib/chock-container.zig` says a tool call does not run inside a container:
//! the image is a source of files and Chock's own sandbox is still the whole
//! boundary. That claim is only worth what a measurement makes it worth, and
//! this program is the measurement. It builds a `Sandbox.Config` out of the
//! mount set the module really produced and starts a program out of the image.
//! No container runtime is involved at any point in this file.
//!
//! It is a separate program for the reason every sandbox probe in this project
//! is one: `Sandbox.spawn` calls `fork`, `fork` carries only the calling thread
//! into the child, so its caller must be single threaded. The Zig test runner
//! that runs `test/container/sandbox.zig` is not that caller. This is.
//!
//! **Nothing here writes to standard error.** `test/proto/lock.zig` holds this
//! project's rule, and the exemption list it carries lives in a file this
//! program does not own. Every answer travels as an exit status instead, which is
//! enough: the whole question is whether a program from the image ran and what
//! it exited with.
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
//!   254                             the sandboxed program was signalled

const std = @import("std");
const sandbox = @import("chock-sandbox");

const bad_usage = 251;
const probe_fault = 252;
const spawn_refused = 253;
const program_signalled = 254;

/// The field separator inside one blob line. The same 0x01 every other probe
/// in this project uses.
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

    // A procfs of the sandbox's own. Every real toolchain reads something
    // under `/proc`, and an image never carries one. This is why `/proc` is in
    // `Image.sandbox_owns`.
    mounts.append(arena, .{ .proc = .{} }) catch return probe_fault;
    rules.append(arena, .{ .path = "/proc", .access = sandbox.landlock.AccessFs.read_only }) catch
        return probe_fault;

    // `/dev/null` from the host, which is a device node and not something the
    // image can supply: `std.tar` writes no device nodes, and an exported image
    // holds empty ordinary files where its own were. This is why `/dev` is in
    // `Image.sandbox_owns`.
    //
    // Not read only. `namespace.zig`'s own `markReadOnly` also sets `NODEV` on
    // a read only mount, which then refuses to open the device node at all.
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
        // **The default, stated anyway.** A tool call over an image gets the
        // same network isolation every other tool call gets, because the
        // sandbox is unchanged by where the files came from.
        .network = .none,
    }, argv, null, null) catch return spawn_refused;

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

        // **A directory right over a regular file is refused by the kernel**,
        // `EINVAL`, which `lib/chock-sandbox/linux/landlock.zig` measured on
        // kernel 6.18.42. The mount's own kind is what picks the rule, and it
        // comes from `Image.Mount.kind`.
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
