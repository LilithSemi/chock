//! One `Image.load` against one image cache directory, as its own process.
//! `test/container/concurrent.zig` starts several of these at once, because two
//! loads in one test binary share a lock and show nothing about the race.

const std = @import("std");
const chock_container = @import("chock-container");

const Image = chock_container.Image;
const Runtime = chock_container.Runtime;

// Every answer is an exit status. Nothing here writes to standard error, which
// is the rule `test/proto/lock.zig` holds for the whole build.
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

/// False the first time the mount set is not whole, during `hold_ms`.
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
fn whole(io: std.Io, image: *const Image) bool {
    // A base image has `/etc`, `/usr` and more. A shorter set means the tree was
    // read while another process rebuilt it.
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
