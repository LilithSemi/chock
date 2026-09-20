//! Chock's own sandbox, over a root filesystem that came out of a container
//! image. No container runtime runs at any point, and a test skips when no
//! runtime is installed. `Sandbox.spawn` calls `fork`, whose caller must be
//! single threaded, so each test starts `rootfs_probe.zig` and reads its status.

const std = @import("std");
const chock_container = @import("chock-container");
const sandbox = @import("chock-sandbox");

const Image = chock_container.Image;
const Runtime = chock_container.Runtime;

// The test runner panics on unknown argv, so build.zig embeds the probe path.
const probe_path = @import("rootfs_probe_path").rootfs_probe_path;

const test_image = "alpine:3.20";

/// Kept in step with `rootfs_probe.zig`'s own status by name.
const spawn_refused = 253;

const Arranged = struct {
    arena: std.heap.ArenaAllocator,
    env: std.process.Environ.Map,
    tmp: std.testing.TmpDir,
    image: Image,
    root: []const u8,
    mounts_blob: []const u8,
    env_blob: []const u8,

    fn deinit(self: *Arranged) void {
        self.image.deinit(std.testing.io);
        self.tmp.cleanup();
        self.env.deinit();
        self.arena.deinit();
    }
};

fn arrangeOrSkip(allocator: std.mem.Allocator) !Arranged {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    var env = try std.testing.environ.createMap(allocator);
    errdefer env.deinit();

    const found = switch (try Runtime.detect(arena.allocator(), std.testing.io, &env, null)) {
        .not_installed, .refused => return error.SkipZigTest,
        .ready => |value| value,
    };

    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(std.testing.io, &buffer);
    const scratch = buffer[0..length];

    try tmp.dir.createDir(std.testing.io, "cache", .default_dir);
    try tmp.dir.createDir(std.testing.io, "root", .default_dir);

    const cache_dir = try std.fs.path.join(arena.allocator(), &.{ scratch, "cache" });
    const root = try std.fs.path.join(arena.allocator(), &.{ scratch, "root" });

    const host = found.host(&env, null);
    const image = switch (try Image.load(allocator, std.testing.io, .{
        .reference = test_image,
        .cache_dir = cache_dir,
        .kind = found.kind,
        .trust = found.trust,
        .runner = host.runner(),
    })) {
        .refused => |text| {
            allocator.free(text);
            return error.SkipZigTest;
        },
        .provided => |value| value,
    };
    errdefer {
        var owned = image;
        owned.deinit(std.testing.io);
    }

    // Built before the struct literal, never inside it. `arena` is copied by
    // value below, so a block allocated inside the literal is never freed.
    const mounts_text = try mountsBlob(arena.allocator(), image);
    const env_text = try envBlob(arena.allocator(), image);

    return .{
        .arena = arena,
        .env = env,
        .tmp = tmp,
        .image = image,
        .root = root,
        .mounts_blob = mounts_text,
        .env_blob = env_text,
    };
}

fn mountsBlob(arena: std.mem.Allocator, image: Image) ![]const u8 {
    var text: std.ArrayList(u8) = .empty;
    for (image.mounts) |mount| {
        try text.print(arena, "{s}\x01{s}\x01{c}\n", .{
            mount.source,
            mount.target,
            @as(u8, switch (mount.kind) {
                .directory => 'd',
                .file => 'f',
            }),
        });
    }
    return text.toOwnedSlice(arena);
}

fn envBlob(arena: std.mem.Allocator, image: Image) ![]const u8 {
    var text: std.ArrayList(u8) = .empty;
    for (image.variables) |record| {
        try std.testing.expect(std.mem.indexOfScalar(u8, record, '\n') == null);
        try text.print(arena, "{s}\n", .{record});
    }
    return text.toOwnedSlice(arena);
}

fn runInside(arranged: *const Arranged, allocator: std.mem.Allocator, argv: []const []const u8) !u8 {
    var command: std.ArrayList([]const u8) = .empty;
    defer command.deinit(allocator);
    try command.appendSlice(allocator, &.{
        probe_path,
        arranged.root,
        arranged.image.workdir,
        arranged.mounts_blob,
        arranged.env_blob,
    });
    try command.appendSlice(allocator, argv);

    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = command.items,
        .environ_map = &arranged.env,
        // `zig build` reads a run step that wrote to standard error as failed.
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    const code: u8 = switch (result.term) {
        .exited => |c| c,
        else => 255,
    };
    if (code == sandbox.namespace.nothing_measured_exit_status) return error.SkipZigTest;
    return code;
}

test "a program out of the image runs in Chock's own sandbox, and its status comes back" {
    const allocator = std.testing.allocator;
    var arranged = try arrangeOrSkip(allocator);
    defer arranged.deinit();

    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{ "/bin/busybox", "true" }),
    );

    try std.testing.expectEqual(
        @as(u8, 7),
        try runInside(&arranged, allocator, &.{ "/bin/busybox", "sh", "-c", "exit 7" }),
    );
}

test "the sandbox root really is the image, and the host tree is not reachable" {
    const allocator = std.testing.allocator;
    var arranged = try arrangeOrSkip(allocator);
    defer arranged.deinit();

    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{
            "/bin/busybox", "sh", "-c", "[ -f /etc/alpine-release ] || exit 9",
        }),
    );

    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{
            "/bin/busybox", "sh", "-c", "[ -e /nix/store ] && exit 9; exit 0",
        }),
    );
}

test "an absolute link inside the image resolves once the image is the root" {
    // Alpine's `/bin/sh` links to `/bin/busybox`, which a NixOS host lacks.
    const allocator = std.testing.allocator;
    var arranged = try arrangeOrSkip(allocator);
    defer arranged.deinit();

    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{ "/bin/sh", "-c", "exit 0" }),
    );
}

test "the network namespace still applies over an image" {
    // The namespace is compared, never a connection. `wget` also fails with no
    // name to resolve, which would pass over the host's own namespace.
    const allocator = std.testing.allocator;
    var arranged = try arrangeOrSkip(allocator);
    defer arranged.deinit();

    var buffer: [64]u8 = undefined;
    const length = try std.Io.Dir.readLinkAbsolute(std.testing.io, "/proc/self/ns/net", &buffer);
    const host_namespace = buffer[0..length];
    try std.testing.expect(std.mem.startsWith(u8, host_namespace, "net:["));

    const script = try std.fmt.allocPrint(
        allocator,
        "[ \"$(readlink /proc/self/ns/net)\" = \"{s}\" ] && exit 9; exit 0",
        .{host_namespace},
    );
    defer allocator.free(script);

    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{ "/bin/busybox", "sh", "-c", script }),
    );

    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{
            "/bin/busybox",                                              "sh", "-c",
            "[ $(ifconfig -a | grep -c 'Link encap') -eq 1 ] || exit 9",
        }),
    );
}

test "the pid namespace still applies over an image" {
    const allocator = std.testing.allocator;
    var arranged = try arrangeOrSkip(allocator);
    defer arranged.deinit();

    var buffer: [64]u8 = undefined;
    const length = try std.Io.Dir.readLinkAbsolute(std.testing.io, "/proc/self/ns/pid", &buffer);
    const host_namespace = buffer[0..length];
    try std.testing.expect(std.mem.startsWith(u8, host_namespace, "pid:["));

    const script = try std.fmt.allocPrint(
        allocator,
        "[ \"$(readlink /proc/self/ns/pid)\" = \"{s}\" ] && exit 9; exit 0",
        .{host_namespace},
    );
    defer allocator.free(script);

    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{ "/bin/busybox", "sh", "-c", script }),
    );

    // A `/proc` that is not mounted makes `grep -c` answer 0, so the upper
    // bound alone would report isolation over nothing.
    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{
            "/bin/busybox",                                                                               "sh", "-c",
            "n=$(ls /proc | grep -c '^[0-9]'); [ \"$n\" -ge 2 ] || exit 10; [ \"$n\" -le 16 ] || exit 9",
        }),
    );

    try std.testing.expect(spawn_refused != 0);
}

test "the mount set the sandbox was given is the one the module produced" {
    const allocator = std.testing.allocator;
    var arranged = try arrangeOrSkip(allocator);
    defer arranged.deinit();

    var lines: usize = 0;
    var it = std.mem.splitScalar(u8, arranged.mounts_blob, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\x01');
        const source = fields.next().?;
        const target = fields.next().?;
        try std.testing.expectEqualStrings(arranged.image.mounts[lines].source, source);
        try std.testing.expectEqualStrings(arranged.image.mounts[lines].target, target);
        lines += 1;
    }
    try std.testing.expectEqual(arranged.image.mounts.len, lines);
    try std.testing.expect(lines > 0);
}
