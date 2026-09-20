//! `chock-container` against a real container runtime and a real image.
//!
//! A test skips when no runtime is installed, or when the image is not on this
//! machine, because these tests never fetch. Run `docker pull alpine:3.20`
//! first. The Podman half of `Runtime` has never run against a real Podman.

const std = @import("std");
const chock_container = @import("chock-container");

const Image = chock_container.Image;
const Runtime = chock_container.Runtime;

const test_image = "alpine:3.20";

const Ready = struct {
    arena: std.heap.ArenaAllocator,
    env: std.process.Environ.Map,
    found: Runtime.Found,

    fn deinit(self: *Ready) void {
        self.env.deinit();
        self.arena.deinit();
    }
};

fn runtimeOrSkip(allocator: std.mem.Allocator) !Ready {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    var env = try std.testing.environ.createMap(allocator);
    errdefer env.deinit();

    const answer = try Runtime.detect(arena.allocator(), std.testing.io, &env, null);
    switch (answer) {
        .not_installed, .refused => return error.SkipZigTest,
        .ready => |found| return .{ .arena = arena, .env = env, .found = found },
    }
}

const Loaded = struct {
    ready: Ready,
    tmp: std.testing.TmpDir,
    image: Image,

    fn deinit(self: *Loaded) void {
        self.image.deinit(std.testing.io);
        self.tmp.cleanup();
        self.ready.deinit();
    }
};

fn loadOrSkip(allocator: std.mem.Allocator) !Loaded {
    var ready = try runtimeOrSkip(allocator);
    errdefer ready.deinit();

    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(std.testing.io, &buffer);
    const cache_dir = buffer[0..length];

    const host = ready.found.host(&ready.env, null);
    const answer = try Image.load(allocator, std.testing.io, .{
        .reference = test_image,
        .cache_dir = cache_dir,
        .kind = ready.found.kind,
        .trust = ready.found.trust,
        .runner = host.runner(),
    });

    switch (answer) {
        .refused => |text| {
            allocator.free(text);
            return error.SkipZigTest;
        },
        .provided => |image| return .{ .ready = ready, .tmp = tmp, .image = image },
    }
}

test "a real runtime answers, and says whether it is rootless" {
    var ready = try runtimeOrSkip(std.testing.allocator);
    defer ready.deinit();

    try std.testing.expect(std.fs.path.isAbsolute(ready.found.program));
    try std.testing.expect(std.mem.endsWith(u8, ready.found.program, ready.found.kind.program()));

    switch (ready.found.trust) {
        .user_only => try std.testing.expect(!ready.found.trust.isPrivileged()),
        .root_daemon, .unknown => try std.testing.expect(ready.found.trust.isPrivileged()),
    }
    try std.testing.expect(ready.found.trust.text().len > 0);
}

test "a real image gives the environment its own config states" {
    var loaded = try loadOrSkip(std.testing.allocator);
    defer loaded.deinit();

    try std.testing.expect(loaded.image.digest.len > 0);

    // PATH comes from the image. Alpine keeps `ls` and `cat` as BusyBox links.
    var path: ?[]const u8 = null;
    for (loaded.image.variables) |record| {
        if (std.mem.startsWith(u8, record, "PATH=")) path = record["PATH=".len..];
    }
    const found = path orelse return error.TheImageStatesNoPath;
    try std.testing.expect(std.mem.indexOf(u8, found, "/bin") != null);
    try std.testing.expect(std.mem.indexOf(u8, found, "/nix/store") == null);

    try std.testing.expect(loaded.image.workdir.len > 0);
    try std.testing.expect(loaded.image.workdir[0] == '/');
}

test "a real image becomes a tree this user owns, with no privilege at all" {
    var loaded = try loadOrSkip(std.testing.allocator);
    defer loaded.deinit();

    try std.testing.expect(loaded.image.extracted);

    var tree = try std.Io.Dir.openDirAbsolute(std.testing.io, loaded.image.rootfs, .{ .iterate = true });
    defer tree.close(std.testing.io);

    const shell = try std.fs.path.join(std.testing.allocator, &.{ loaded.image.rootfs, "bin/busybox" });
    defer std.testing.allocator.free(shell);
    const stat = try std.Io.Dir.cwd().statFile(std.testing.io, shell, .{});
    try std.testing.expect(stat.kind == .file);
    try std.testing.expect(stat.permissions.toMode() & 0o111 != 0);

    // A write is the only proof of ownership. No field of `Stat` reports it.
    {
        var written = try tree.createFile(std.testing.io, "chock-ownership-probe", .{});
        written.close(std.testing.io);
    }
    try tree.deleteFile(std.testing.io, "chock-ownership-probe");
}

test "an absolute link inside the image only resolves once the tree is the root" {
    // Alpine writes `/bin/sh` as a symbolic link to the absolute path
    // `/bin/busybox`, so the link is broken outside the sandbox and right in it.
    var loaded = try loadOrSkip(std.testing.allocator);
    defer loaded.deinit();

    const link = try std.fs.path.join(std.testing.allocator, &.{ loaded.image.rootfs, "bin/sh" });
    defer std.testing.allocator.free(link);

    const without_following = try std.Io.Dir.cwd().statFile(
        std.testing.io,
        link,
        .{ .follow_symlinks = false },
    );
    try std.testing.expectEqual(std.Io.File.Kind.sym_link, without_following.kind);

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try std.Io.Dir.readLinkAbsolute(std.testing.io, link, &buffer);
    try std.testing.expect(std.fs.path.isAbsolute(buffer[0..length]));
}

test "no set-user-id file reaches the disk out of a real image" {
    // `std.tar.extract` keeps only the executable bit, so a set-user-id bit in
    // the tar never reaches the disk. Alpine ships none, so the walk finds none.
    var loaded = try loadOrSkip(std.testing.allocator);
    defer loaded.deinit();

    var tree = try std.Io.Dir.openDirAbsolute(std.testing.io, loaded.image.rootfs, .{ .iterate = true });
    defer tree.close(std.testing.io);

    var walker = try tree.walk(std.testing.allocator);
    defer walker.deinit();

    var files: usize = 0;
    var offenders: usize = 0;
    while (try walker.next(std.testing.io)) |entry| {
        if (entry.kind != .file) continue;
        files += 1;
        const stat = entry.dir.statFile(std.testing.io, entry.basename, .{ .follow_symlinks = false }) catch continue;
        const mode = stat.permissions.toMode();
        if (mode & 0o4000 != 0 or mode & 0o2000 != 0) offenders += 1;
    }

    try std.testing.expectEqual(@as(usize, 0), offenders);
    // A tree with nothing in it would pass the loop above and prove nothing.
    try std.testing.expect(files > 50);
}

test "the mount set of a real image binds the image and never the sandbox's own paths" {
    var loaded = try loadOrSkip(std.testing.allocator);
    defer loaded.deinit();

    try std.testing.expect(loaded.image.mounts.len > 0);

    var has_bin = false;
    var has_usr = false;
    for (loaded.image.mounts) |mount| {
        try std.testing.expect(std.mem.startsWith(u8, mount.source, loaded.image.rootfs));
        try std.testing.expect(mount.read_only);
        try std.testing.expect(std.fs.path.isAbsolute(mount.target));
        const stat = try std.Io.Dir.cwd().statFile(std.testing.io, mount.source, .{ .follow_symlinks = false });
        switch (mount.kind) {
            .directory => try std.testing.expectEqual(std.Io.File.Kind.directory, stat.kind),
            .file => try std.testing.expectEqual(std.Io.File.Kind.file, stat.kind),
        }

        for (Image.sandbox_owns) |owned| {
            const forbidden = try std.fmt.allocPrint(std.testing.allocator, "/{s}", .{owned});
            defer std.testing.allocator.free(forbidden);
            try std.testing.expect(!std.mem.eql(u8, mount.target, forbidden));
        }

        if (std.mem.eql(u8, mount.target, "/bin")) has_bin = true;
        if (std.mem.eql(u8, mount.target, "/usr")) has_usr = true;
    }

    // Debian's `/bin` is a symbolic link and not a directory, so it fails here.
    try std.testing.expect(has_bin);
    try std.testing.expect(has_usr);
}

test "a second load reads the cache and does not extract the image again" {
    const allocator = std.testing.allocator;

    var ready = try runtimeOrSkip(allocator);
    defer ready.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(std.testing.io, &buffer);
    const cache_dir = buffer[0..length];

    const host = ready.found.host(&ready.env, null);
    const options = Image.Options{
        .reference = test_image,
        .cache_dir = cache_dir,
        .kind = ready.found.kind,
        .trust = ready.found.trust,
        .runner = host.runner(),
    };

    var first = switch (try Image.load(allocator, std.testing.io, options)) {
        .refused => |text| {
            allocator.free(text);
            return error.SkipZigTest;
        },
        .provided => |image| image,
    };
    defer first.deinit(std.testing.io);
    try std.testing.expect(first.extracted);

    var second = switch (try Image.load(allocator, std.testing.io, options)) {
        .refused => return error.TestUnexpectedResult,
        .provided => |image| image,
    };
    defer second.deinit(std.testing.io);

    try std.testing.expect(!second.extracted);
    try std.testing.expectEqualStrings(first.digest, second.digest);
    try std.testing.expectEqual(first.mounts.len, second.mounts.len);
}

test "an image that is not on this machine is refused, and no network is reached" {
    var ready = try runtimeOrSkip(std.testing.allocator);
    defer ready.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(std.testing.io, &buffer);

    const host = ready.found.host(&ready.env, null);
    const answer = try Image.load(std.testing.allocator, std.testing.io, .{
        .reference = "chock-no-such-image-anywhere:0.0.0",
        .cache_dir = buffer[0..length],
        .kind = ready.found.kind,
        .trust = ready.found.trust,
        .runner = host.runner(),
    });

    switch (answer) {
        .provided => |image| {
            var owned = image;
            owned.deinit(std.testing.io);
            return error.TestUnexpectedResult;
        },
        .refused => |text| {
            defer std.testing.allocator.free(text);
            try std.testing.expect(std.mem.indexOf(u8, text, "chock-no-such-image-anywhere") != null);
            try std.testing.expect(std.mem.indexOf(u8, text, "pull") != null);
        },
    }
}
