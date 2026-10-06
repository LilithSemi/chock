//! The program `test/workspace/darwin_escape.zig` drives. It rebuilds a real
//! `Sandbox.Config` from the blobs on its command line, calls `chock_sandbox.spawn`,
//! and reports the kernel's answer as an exit status.

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

/// Inside a `nix build` the builder already holds a Seatbelt profile, and `spawn` answers `LandlockRestrictFailed`.
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
