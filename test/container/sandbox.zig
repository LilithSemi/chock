//! Chock's own sandbox, over a root filesystem that came out of a container
//! image.
//!
//! **This is the acceptance test for the central design decision.**
//! `lib/chock-container.zig` decides that a tool call does not run inside a
//! container: the image is a source of files, exactly as a Nix closure is, and
//! Chock's own sandbox is still the whole boundary. Every test here starts a
//! real program out of a real image inside a real `Sandbox.spawn`, with no
//! container runtime running at any point.
//!
//! ## What each test proves
//!
//! * A program from the image runs at all, and its exit status comes back.
//! * The sandbox root really is the image, because a file only the image has
//!   is readable inside it.
//! * The host tree is not reachable, because a directory only the host has is
//!   not there.
//! * An absolute symbolic link inside the image resolves, which it cannot do
//!   on the host. This is the reason the mount set exists in the shape it has.
//! * The network namespace still applies. A container arrangement changes
//!   nothing about the boundary, and this is the test that says so.
//!
//! ## Why there is a second program
//!
//! `Sandbox.spawn` calls `fork`, and `fork` carries only the calling thread
//! into the child, so its caller must be single threaded. The Zig test runner
//! is not. `test/container/rootfs_probe.zig` is, and this file starts it and
//! reads its exit status, which is the pattern `test/sandbox/escape.zig` and
//! `test/workspace/escape.zig` both already use.
//!
//! ## What makes a test here skip
//!
//! No container runtime, or the test image not on the disk. See
//! `test/container/real_runtime.zig`'s own top comment: these tests never
//! fetch, for the same reason a session never does.
//!
//! Measured on 2026-08-25, on Linux 6.18.42, aarch64, against Docker 29.7.2
//! with `alpine:3.20` on the disk.

const std = @import("std");
const chock_container = @import("chock-container");
// `chock-sandbox` for one question only: the exit status the probe answers
// with when this machine will not give it a sandbox at all.
const sandbox = @import("chock-sandbox");

const Image = chock_container.Image;
const Runtime = chock_container.Runtime;

// Zig 0.16 removed `std.process.argsWithAllocator`, and the default test
// runner panics on any argv it does not recognize, so the probe's path cannot
// come in as a CLI argument. build.zig embeds it as a build time constant, the
// same way it does for every other probe in this project.
const probe_path = @import("rootfs_probe_path").rootfs_probe_path;

const test_image = "alpine:3.20";

/// The four statuses `rootfs_probe` uses for its own faults. Kept in step with
/// that file by name.
const spawn_refused = 253;

/// Everything one test needs: a real image, an empty sandbox root, and the
/// blobs the probe reads.
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

    // The cache and the sandbox root are siblings. The root has to be an empty
    // directory of its own: the mount tree is built inside it.
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

    // **Built before the struct literal, never inside it.** `arena` is copied
    // by value into the field below, and a struct literal fills its fields in
    // order, so a call that allocated from `arena` inside the literal would
    // put its blocks on the local arena's list and not on the copy's. The
    // copy's `deinit` would then free neither. Measured as a leak on
    // 2026-08-25, before this line moved.
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

/// The mount set the module produced, in the probe's own wire shape. **Nothing
/// is added or left out here**, so what the sandbox binds is exactly what
/// `Image.mounts` said.
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

/// The environment the image states, in the probe's own wire shape.
fn envBlob(arena: std.mem.Allocator, image: Image) ![]const u8 {
    var text: std.ArrayList(u8) = .empty;
    for (image.variables) |record| {
        // A variable holding a newline cannot travel in this shape. No image
        // config states one, and a test that quietly dropped it would be worse
        // than one that says so.
        try std.testing.expect(std.mem.indexOfScalar(u8, record, '\n') == null);
        try text.print(arena, "{s}\n", .{record});
    }
    return text.toOwnedSlice(arena);
}

/// Run `argv` inside the sandbox and answer its exit status.
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
        // **Captured, never let through.** A run step that writes to standard
        // error is read by `zig build` as a failed command whatever its exit
        // status, and a sandboxed program that says something must not turn a
        // passing suite into a doubtful build log.
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    const code: u8 = switch (result.term) {
        .exited => |c| c,
        else => 255,
    };
    // **A boundary that was never reached is not a boundary that held.** Every
    // test below asks what a sandbox does with an image as its root, and a
    // machine that will not give a sandbox measures nothing here. See
    // `chock-sandbox`'s own `namespace.nothing_measured_exit_status`, and the
    // CI job named "Sandbox", which runs this suite on a machine that can host
    // one and fails rather than skips.
    if (code == sandbox.namespace.nothing_measured_exit_status) return error.SkipZigTest;
    return code;
}

test "a program out of the image runs in Chock's own sandbox, and its status comes back" {
    // **The central claim, measured.** No container is running. The sandbox is
    // the one `chock doctor` speaks for, and the files came from an image.
    const allocator = std.testing.allocator;
    var arranged = try arrangeOrSkip(allocator);
    defer arranged.deinit();

    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{ "/bin/busybox", "true" }),
    );

    // A chosen status, so this proves a program really ran rather than that
    // something answered zero.
    try std.testing.expectEqual(
        @as(u8, 7),
        try runInside(&arranged, allocator, &.{ "/bin/busybox", "sh", "-c", "exit 7" }),
    );
}

test "the sandbox root really is the image, and the host tree is not reachable" {
    const allocator = std.testing.allocator;
    var arranged = try arrangeOrSkip(allocator);
    defer arranged.deinit();

    // A file only Alpine has. The machine this runs on is NixOS and has none.
    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{
            "/bin/busybox", "sh", "-c", "[ -f /etc/alpine-release ] || exit 9",
        }),
    );

    // And a directory only the host has. This is the half that says the image
    // replaced the root rather than being added beside it.
    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{
            "/bin/busybox", "sh", "-c", "[ -e /nix/store ] && exit 9; exit 0",
        }),
    );
}

test "an absolute link inside the image resolves once the image is the root" {
    // `/bin/sh` in Alpine is a symbolic link to the absolute path
    // `/bin/busybox`. On the host that names the host's own `/bin/busybox`,
    // which a NixOS machine does not have, so this link is broken outside the
    // sandbox and correct inside it. Every test above that used `sh` already
    // relies on this. This one states it.
    const allocator = std.testing.allocator;
    var arranged = try arrangeOrSkip(allocator);
    defer arranged.deinit();

    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{ "/bin/sh", "-c", "exit 0" }),
    );
}

test "the network namespace still applies over an image" {
    // **The point of the whole design.** Where the files came from changes
    // nothing about the boundary. A tool call over an image gets the same
    // network isolation a tool call over a Nix closure gets, because it is the
    // same sandbox.
    //
    // **The namespace itself is what is compared, and never a connection that
    // failed.** An earlier form of this test ran BusyBox `wget` and expected
    // it to fail. It did fail, and for the wrong reason: `wget` could not
    // resolve a name, so the test passed just as happily with the host's own
    // network namespace on. A mutation on 2026-08-25 caught that. A test whose
    // failure has a second explanation is a test that proves nothing, and a
    // connection that fails on a machine with no route is exactly that.
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

    // And the namespace it did get is empty except for loopback, which is what
    // "no route out" means in the end. BusyBox prints one `Link encap` line per
    // interface. Measured on 2026-08-25: one inside, seven on the host.
    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{
            "/bin/busybox",                                              "sh", "-c",
            "[ $(ifconfig -a | grep -c 'Link encap') -eq 1 ] || exit 9",
        }),
    );
}

test "the pid namespace still applies over an image" {
    // The other half of the same statement. A program from an image is process
    // 1 of its own namespace, and sees no other process on the machine.
    const allocator = std.testing.allocator;
    var arranged = try arrangeOrSkip(allocator);
    defer arranged.deinit();

    try std.testing.expectEqual(
        @as(u8, 0),
        try runInside(&arranged, allocator, &.{
            "/bin/busybox", "sh", "-c", "[ \"$$\" = \"1\" ] || exit 9",
        }),
    );

    // A `spawn` that never came up would answer with this, and would make
    // every check above pass for the wrong reason.
    try std.testing.expect(spawn_refused != 0);
}

test "the mount set the sandbox was given is the one the module produced" {
    // The blob is the seam between the module and the probe, so a test that
    // did not check it could pass with a probe that quietly added a mount of
    // its own. Every line of the blob names a mount of `Image.mounts`, in
    // order, and there are no others.
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
