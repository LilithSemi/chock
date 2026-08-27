//! `chock-container` against a real container runtime and a real image.
//!
//! **This project has been bitten by code that only ever met a stand-in.** It
//! once shipped an LSP client that had never worked against a real server,
//! because both fakes accepted what no real one would. The tests beside the
//! module drive parsers and decisions over buffers, which is right and is not
//! enough. Only a real runtime can say that these are the right commands, that
//! `--format {{json .}}` really answers with the fields this reads, and that an
//! image really becomes a tree an unprivileged user can read.
//!
//! ## What makes a test here skip rather than fail
//!
//! Two things:
//!
//! 1. **No container runtime is installed.** Nothing here can run then, and a
//!    machine without one is an ordinary machine.
//! 2. **The test image is not on this machine.** These tests never fetch. A
//!    test that reaches a registry is a test that fails when a network does,
//!    and `Image.Options.pull` defaults to `.never` for the same reason a
//!    session does not fetch. Run `docker pull alpine:3.20`, or the same with
//!    `podman`, to make these tests run.
//!
//! A skip says nothing on the terminal. `test/proto/lock.zig` holds this
//! project's rule that no test writes to standard error, because `zig build`
//! reads any run step that wrote there as a failed command whatever its exit
//! status.
//!
//! ## What was really run, and when
//!
//! Every test below ran on 2026-08-25, on Linux 6.18.42, aarch64, against
//! Docker 29.7.2 with `alpine:3.20` on the disk. The extracted tree was
//! compared against the same image unpacked by GNU `tar`, and the two matched
//! exactly: 90 regular files, 334 symbolic links, 99 directories.
//!
//! **No Podman was installed on that machine**, so the Podman half of
//! `Runtime` has never run. See `lib/chock-container/Runtime.zig`'s own top
//! comment for what that leaves unverified and how small it was kept.

const std = @import("std");
const chock_container = @import("chock-container");

const Image = chock_container.Image;
const Runtime = chock_container.Runtime;

/// The image these tests use. Small, and one every machine can fetch.
const test_image = "alpine:3.20";

/// A real runtime, or null when this machine has none. Every test starts here.
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

/// A real load of `test_image`, or a skip. The caller owns the image and the
/// temporary directory it was extracted into.
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

    // The program is an absolute path, which is what makes a missing runtime a
    // refusal before any child exists.
    try std.testing.expect(std.fs.path.isAbsolute(ready.found.program));
    try std.testing.expect(std.mem.endsWith(u8, ready.found.program, ready.found.kind.program()));

    // **A trust position that was really measured, and never guessed.** On the
    // machine this was written on the answer was `root_daemon`, because Docker
    // 29.7.2 listed its security options without `name=rootless`. Another
    // machine answers differently, so the test pins the property that matters:
    // an answer that is not `user_only` reads as privileged.
    switch (ready.found.trust) {
        .user_only => try std.testing.expect(!ready.found.trust.isPrivileged()),
        .root_daemon, .unknown => try std.testing.expect(ready.found.trust.isPrivileged()),
    }
    try std.testing.expect(ready.found.trust.text().len > 0);
}

test "a real image gives the environment its own config states" {
    var loaded = try loadOrSkip(std.testing.allocator);
    defer loaded.deinit();

    // The digest is a content hash the runtime handed back, so the cache stamp
    // means something.
    try std.testing.expect(loaded.image.digest.len > 0);

    // **PATH comes from the image, not from the host.** This is the whole
    // reason the environment is read at all. Measured by hand on 2026-08-25: a
    // shell from an extracted Alpine tree, run with the host's own PATH, could
    // not find `ls`, `cat` or `id`, because every one of them is a BusyBox link
    // under the image's own directories.
    var path: ?[]const u8 = null;
    for (loaded.image.variables) |record| {
        if (std.mem.startsWith(u8, record, "PATH=")) path = record["PATH=".len..];
    }
    const found = path orelse return error.TheImageStatesNoPath;
    try std.testing.expect(std.mem.indexOf(u8, found, "/bin") != null);
    // And it is not this machine's own PATH, which on a Nix host names the
    // store in every entry.
    try std.testing.expect(std.mem.indexOf(u8, found, "/nix/store") == null);

    // An image that states no working directory means the root, never an empty
    // string, which no process can start in.
    try std.testing.expect(loaded.image.workdir.len > 0);
    try std.testing.expect(loaded.image.workdir[0] == '/');
}

test "a real image becomes a tree this user owns, with no privilege at all" {
    // **The measurement the whole design rests on.** If an image could only be
    // unpacked by root, the container would have to be the boundary. It can be
    // unpacked by anybody, so it is a source of files and nothing more.
    var loaded = try loadOrSkip(std.testing.allocator);
    defer loaded.deinit();

    try std.testing.expect(loaded.image.extracted);

    var tree = try std.Io.Dir.openDirAbsolute(std.testing.io, loaded.image.rootfs, .{ .iterate = true });
    defer tree.close(std.testing.io);

    // A real program is there, and it is really executable.
    const shell = try std.fs.path.join(std.testing.allocator, &.{ loaded.image.rootfs, "bin/busybox" });
    defer std.testing.allocator.free(shell);
    const stat = try std.Io.Dir.cwd().statFile(std.testing.io, shell, .{});
    try std.testing.expect(stat.kind == .file);
    try std.testing.expect(stat.permissions.toMode() & 0o111 != 0);

    // **This user owns the tree**, which a write proves directly and no field
    // of `Stat` reports. An extraction that needed privilege could not do this.
    {
        var written = try tree.createFile(std.testing.io, "chock-ownership-probe", .{});
        written.close(std.testing.io);
    }
    try tree.deleteFile(std.testing.io, "chock-ownership-probe");
}

test "an absolute link inside the image only resolves once the tree is the root" {
    // **Why the tree has to be mounted at `/` and cannot simply be read where
    // it lies.** Measured on 2026-08-25: Alpine writes `/bin/sh` as a symbolic
    // link to the absolute path `/bin/busybox`. Followed from the host that
    // names the host's own `/bin/busybox`, which a NixOS machine does not have,
    // so the link is broken outside the sandbox and correct inside it.
    var loaded = try loadOrSkip(std.testing.allocator);
    defer loaded.deinit();

    const link = try std.fs.path.join(std.testing.allocator, &.{ loaded.image.rootfs, "bin/sh" });
    defer std.testing.allocator.free(link);

    // The link itself is there.
    const without_following = try std.Io.Dir.cwd().statFile(
        std.testing.io,
        link,
        .{ .follow_symlinks = false },
    );
    try std.testing.expectEqual(std.Io.File.Kind.sym_link, without_following.kind);

    // And what it names is an absolute path inside the image, so the mount set
    // this module builds is the thing that makes it work.
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try std.Io.Dir.readLinkAbsolute(std.testing.io, link, &buffer);
    try std.testing.expect(std.fs.path.isAbsolute(buffer[0..length]));
}

test "no set-user-id file reaches the disk out of a real image" {
    // **A rule that only a real image can test.** Measured on 2026-08-25:
    // `debian:stable-slim` ships `usr/bin/mount`, `usr/bin/chfn`,
    // `usr/bin/gpasswd` and more with the set-user-id bit on in the tar.
    // `std.tar.extract` keeps only the executable bit, so none of them reaches
    // the disk with it.
    //
    // Alpine ships none, so on Alpine this proves the walk works and finds
    // nothing.
    //
    // **What this can and cannot catch, stated plainly.**
    // `std.tar.ExtractOptions.ModeMode` has two members, `ignore` and
    // `executable_bit_only`, and neither one can write a set-user-id bit. So no
    // change to that option can make this test fail, and a mutation of it is
    // not available. What it does guard is the day somebody replaces the pure
    // Zig extraction with a system `tar -p`, which does write the bit. The walk
    // itself was checked on 2026-08-25 by flagging the executable bit instead:
    // it found 26 files, so the mode really is read and a set bit really would
    // be seen.
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
    // Alpine 3.20 holds 90 regular files, counted by hand on 2026-08-25.
    try std.testing.expect(files > 50);
}

test "the mount set of a real image binds the image and never the sandbox's own paths" {
    var loaded = try loadOrSkip(std.testing.allocator);
    defer loaded.deinit();

    try std.testing.expect(loaded.image.mounts.len > 0);

    var has_bin = false;
    var has_usr = false;
    for (loaded.image.mounts) |mount| {
        // Every source is inside the extracted tree. A source anywhere else
        // would put a directory of the real machine into the sandbox.
        try std.testing.expect(std.mem.startsWith(u8, mount.source, loaded.image.rootfs));
        // Every mount is read only. The tree is shared by every session.
        try std.testing.expect(mount.read_only);
        // And a target is an absolute path inside the sandbox, which is why
        // this arrangement is Linux only.
        try std.testing.expect(std.fs.path.isAbsolute(mount.target));
        // A source that is neither a directory nor a regular file cannot be
        // bound, and the kind is what a caller picks a Landlock rule from.
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

    // A sandbox with no `/bin` is a sandbox nothing starts in. This is the
    // assertion that would have caught a Debian image, whose `/bin` is a
    // symbolic link and not a directory.
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

    // The point: the second load wrote no tree. An extraction of a real image
    // is seconds, and a session that paid it every time would be unusable.
    try std.testing.expect(!second.extracted);
    try std.testing.expectEqualStrings(first.digest, second.digest);
    try std.testing.expectEqual(first.mounts.len, second.mounts.len);
}

test "an image that is not on this machine is refused, and no network is reached" {
    // A reference that no registry has. With `pull` at its default this must be
    // a sentence rather than an attempt to fetch.
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
            // It names the command to run, which is the whole difference
            // between a refusal and a failure.
            try std.testing.expect(std.mem.indexOf(u8, text, "pull") != null);
        },
    }
}
