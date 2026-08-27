//! One `Image.load` against one image cache directory, as its own process.
//!
//! **Two sessions on one image is the ordinary case**, and a shared image cache
//! is what makes the second one cheap. This program is one of those sessions.
//! `test/container/concurrent.zig` starts several at once on one directory and
//! reads what each said, which is the only way to measure the race: the cache
//! is shared through the filesystem, so two `Image.load` calls inside one test
//! binary would contend on the same lock correctly and still prove nothing
//! about two `chock run` commands in two terminals.
//!
//! **Nothing here writes to standard error.** `test/proto/lock.zig` holds the
//! rule for the whole build. Every answer travels as an exit status.
//!
//! **A session lasts, and that is the second thing this measures.** With
//! `<hold-ms>` this program keeps the image it was given and reads its mount
//! set again and again, which is what every tool call of a real session does.
//! A second session that resolves the same directory to another digest used to
//! remove the tree under this one. See
//! `test/container/concurrent.zig` for the numbers.
//!
//! Command line:
//!   load-helper <cache-dir> <reference> [hold-ms]
//!
//! Exit status:
//!   0   the image came out of the cache, and no tree was written
//!   1   this process extracted the image
//!   2   the load refused
//!   3   the load failed
//!   4   the tree it was given is not whole
//!   5   this machine has no container runtime
//!   6   the command line was wrong
//!   7   this program itself ran out of memory

const std = @import("std");
const chock_container = @import("chock-container");

const Image = chock_container.Image;
const Runtime = chock_container.Runtime;

pub const from_cache = 0;
pub const extracted = 1;
pub const refused = 2;
pub const load_failed = 3;
pub const tree_broken = 4;
pub const no_runtime = 5;
pub const bad_usage = 6;
pub const helper_fault = 7;

pub fn main(init: std.process.Init) u8 {
    const arena = init.arena.allocator();

    const args = init.minimal.args.toSlice(arena) catch return helper_fault;
    if (args.len != 3 and args.len != 4) return bad_usage;
    const cache_dir = args[1];
    const reference = args[2];
    const hold_ms: u64 = if (args.len == 4)
        std.fmt.parseInt(u64, args[3], 10) catch return bad_usage
    else
        0;

    const found = switch (Runtime.detect(arena, init.io, init.environ_map, null) catch return no_runtime) {
        .not_installed, .refused => return no_runtime,
        .ready => |value| value,
    };

    var host = found.host(init.environ_map, null);
    const answer = Image.load(init.gpa, init.io, .{
        .reference = reference,
        .cache_dir = cache_dir,
        .kind = found.kind,
        .trust = found.trust,
        .runner = host.runner(),
    }) catch return load_failed;

    switch (answer) {
        .refused => |text| {
            init.gpa.free(text);
            return refused;
        },
        .provided => |image| {
            var owned = image;
            defer owned.deinit(init.io);
            if (!whole(init.io, &owned)) return tree_broken;
            if (!heldFor(init.io, &owned, hold_ms)) return tree_broken;
            return if (owned.extracted) extracted else from_cache;
        },
    }
}

/// Read the mount set again every `check_every_ms` for `hold_ms`, and answer
/// false the first time it is not whole.
///
/// **This is a session, in the one respect that matters here.** A session lives
/// for minutes or hours and every tool call of it binds the same mount set, so
/// the tree has to stay on the disk for all of that time. A helper that loaded
/// and exited at once could never see a second session remove it.
fn heldFor(io: std.Io, image: *const Image, hold_ms: u64) bool {
    if (hold_ms == 0) return true;

    var waited: u64 = 0;
    while (waited < hold_ms) : (waited += check_every_ms) {
        std.Io.sleep(io, .fromMilliseconds(check_every_ms), .awake) catch return false;
        if (!whole(io, image)) return false;
    }
    return true;
}

const check_every_ms: u64 = 25;

/// True when the mount set names a tree that is really on the disk.
///
/// **This is what a torn cache looks like from a session's side.** A second
/// session that removes and rebuilds the tree under this one leaves a mount set
/// naming paths that are gone, and the failure then arrives one tool call into
/// the session with nothing to explain it.
fn whole(io: std.Io, image: *const Image) bool {
    // A base image has `/etc`, `/usr` and more. A set this short means the tree
    // was read while another process was rebuilding it.
    if (image.mounts.len < 4) return false;

    for (image.mounts) |mount| {
        const stat = std.Io.Dir.cwd().statFile(io, mount.source, .{}) catch return false;
        switch (mount.kind) {
            .directory => if (stat.kind != .directory) return false,
            .file => if (stat.kind != .file) return false,
        }
    }
    return true;
}
