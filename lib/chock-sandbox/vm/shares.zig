//! Where a host path is inside a guest.
//!
//! A guest mounts one virtiofs filesystem, and every directory the host offers
//! appears as a name inside it. So a `Config` built on the host names paths the
//! guest has never heard of: `/nix/store` on this machine is
//! `<root>/store` in there. This module rewrites one into the other.
//!
//! ## The share set is derived from the mounts it has to cover
//!
//! `offersFor` walks a `Config` and offers one directory per source it binds.
//! **A set written out beside the mounts goes stale the moment a mount is
//! added**, which is how a session reached a guest that could not place its own
//! git directory: the set named the store, the workspace and the cache, and the
//! workspace's backing binds four more.
//!
//! Two things keep the count inside a guest's 32 offers. Every path under the
//! store folds into one share, which is what makes a dev shell closure of
//! thousands of entries a single offer. And a source already inside an offer of
//! the same writability adds none.
//!
//! **Writability is never merged.** A writable directory inside a read only one
//! stays an offer of its own rather than making the whole parent writable: the
//! share's writability is what the guest's kernel may do, and widening it to save
//! a name widens the boundary.
//!
//! ## What a wrong answer here breaks
//!
//! **A path under no share is a refusal.** A source left as it was would name a
//! path the guest does not have, and a tool call would fail for a reason nobody
//! could read. Worse, it could name a path the guest does have for another
//! reason, and then the sandbox would bind something nobody offered.
//!
//! **A mount that writes must land in a writable share.** The share's writability
//! is what the guest's own kernel may do; a mount's `read_only` is what the
//! sandboxed program may do. A writable mount inside a read only share is a
//! sandbox that cannot work, and answering it silently would have the failure
//! surface as a permission error inside a tool call.

const std = @import("std");

const iface = @import("../Sandbox.zig");
const namespace = @import("../linux/namespace.zig");

/// One directory the host offers the guest.
pub const Share = struct {
    /// The name the guest sees inside its one virtiofs mount. **Chosen by the
    /// host and never by anything that arrived from outside**, for the reason
    /// `lib/chock-core/skills.zig` gives about a name reaching a namespace.
    name: []const u8,
    /// Where it really is on this machine.
    host_path: []const u8,
    /// Whether the guest's kernel may change what is in it.
    writable: bool,
};

pub const Set = struct {
    /// Where the one virtiofs mount is inside the guest.
    root: []const u8,
    shares: []const Share,

    /// The share holding `host_path`, or null. **The longest match wins**: a
    /// session that offers `/work` and `/work/.git` separately means the second
    /// for a path under it, and taking the first would give it the wrong
    /// writability.
    pub fn holding(self: Set, host_path: []const u8) ?Share {
        var best: ?Share = null;
        for (self.shares) |one| {
            if (!underneath(host_path, one.host_path)) continue;
            const longer = if (best) |had| one.host_path.len > had.host_path.len else true;
            if (longer) best = one;
        }
        return best;
    }

    /// Where the guest sees `host_path`, or null when nothing offers it.
    pub fn insideOf(
        self: Set,
        allocator: std.mem.Allocator,
        host_path: []const u8,
    ) std.mem.Allocator.Error!?[]const u8 {
        const share = self.holding(host_path) orelse return null;
        const rest = host_path[share.host_path.len..];
        const trimmed = std.mem.trimStart(u8, rest, "/");
        if (trimmed.len == 0) {
            return try std.fs.path.join(allocator, &.{ self.root, share.name });
        }
        return try std.fs.path.join(allocator, &.{ self.root, share.name, trimmed });
    }
};

/// Why a config cannot be run in this guest. Each one names a path, so a person
/// reading the refusal knows which share is missing.
pub const Fault = union(enum) {
    /// Nothing the host offered holds this path.
    not_offered: []const u8,
    /// The mount writes, and the share holding it is read only.
    needs_writing: []const u8,
    /// A device node of this host's that is not one every kernel makes.
    host_device: []const u8,

    pub fn path(self: Fault) []const u8 {
        return switch (self) {
            .not_offered, .needs_writing, .host_device => |one| one,
        };
    }

    pub fn sentence(self: Fault) []const u8 {
        return switch (self) {
            .not_offered => "no directory offered to the guest holds it",
            .needs_writing => "the mount writes there and the directory offered is read only",
            .host_device => "a guest has only the device nodes its own kernel makes",
        };
    }
};

/// The device nodes every Linux kernel makes.
///
/// **These cross as they are and never through a share.** A guest mounts its own
/// devtmpfs, so `/dev/null` in there is the same device as `/dev/null` out here,
/// and a bind of one names what the host meant. Sharing the host's node instead
/// would put a file where a device belongs.
///
/// A path under `/dev` that is not one of these is refused rather than passed
/// through: a guest does not have the host's other devices, and a mount of one
/// would fail inside for a reason nobody could trace back to here.
pub const guest_device_nodes = [_][]const u8{
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
};

fn isGuestDevice(path: []const u8) bool {
    for (guest_device_nodes) |one| {
        if (std.mem.eql(u8, path, one)) return true;
    }
    return false;
}

pub const Error = std.mem.Allocator.Error || error{
    /// A host path could not be placed in the guest. `fault` says which and why.
    NotPlaceable,
};

/// The most a guest takes. `mirage-fs.Export`'s own bound, and a set past it is
/// refused here rather than by a guest that has already booted.
///
/// **A session does not have all of them.** A guest a daemon started is offered
/// the roots of its own grant before the session says anything, up to sixteen of
/// these, and a session's offer of the same directory replaces one of those
/// rather than taking another. So this bound is the whole budget and the check
/// below is of one spender. The other spender names the number it took when a
/// guest runs out: see `offerShare` in `src/vmm.zig`.
pub const max_offers: usize = 32;

/// The name the store folds into. Every path under `store_root` is read only, so
/// one name covers a closure of any size.
pub const store_share_name = "store";

/// A directory a caller knows a tool call needs, which the session's own config
/// does not name. `offersFor` gives it a name like any other.
pub const Wanted = struct {
    host_path: []const u8,
    writable: bool,
};

pub const OfferError = std.mem.Allocator.Error || error{
    /// More directories than a guest takes. The caller says which session, so
    /// this carries no path of its own.
    TooManyOffers,
};

/// One directory per source `config` binds, so every path it names can be placed.
///
/// `extra` holds sources a tool call adds that the session's own config does not,
/// such as a toolchain's read only mounts. `store_root` folds every path under it
/// into one read only offer, and null offers the store nothing.
///
/// **Give it an arena.** Every name and every path is its own allocation.
pub fn offersFor(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: iface.Config,
    extra: []const Wanted,
    store_root: ?[]const u8,
) OfferError![]const Share {
    var out: std.ArrayList(Share) = .empty;

    // **Offered whether or not this config names a path in it.** A session's own
    // config binds no store path: the closure is added per call, by `withStore`,
    // and a set derived from the session alone would have no store in it when the
    // first call arrived. One offer is also the only shape that fits, because a
    // dev shell closure is thousands of paths and a guest takes 32.
    if (store_root) |root| {
        if (std.Io.Dir.cwd().statFile(io, root, .{})) |_| {
            try out.append(allocator, .{
                .name = store_share_name,
                .host_path = root,
                .writable = false,
            });
        } else |_| {}
    }

    for (config.mounts) |one| switch (one) {
        .bind => |bind| try offer(allocator, io, &out, bind.source, !bind.read_only, store_root),
        .overlay => |over| {
            try offer(allocator, io, &out, over.lower, false, store_root);
            try offer(allocator, io, &out, over.upper, true, store_root);
            try offer(allocator, io, &out, over.work, true, store_root);
        },
        // Neither names a path of the host's.
        .proc, .deny => {},
    };
    for (extra) |one| try offer(allocator, io, &out, one.host_path, one.writable, store_root);

    if (out.items.len > max_offers) return error.TooManyOffers;
    return out.toOwnedSlice(allocator);
}

/// Add the directory holding `source`, unless an offer already covers it.
fn offer(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.ArrayList(Share),
    source: []const u8,
    writes: bool,
    store_root: ?[]const u8,
) std.mem.Allocator.Error!void {
    if (source.len == 0) return;
    // A device node is the guest's own, so no directory is offered for it.
    if (underneath(source, "/dev")) return;

    if (store_root) |root| {
        if (underneath(source, root)) {
            for (out.items) |had| if (std.mem.eql(u8, had.host_path, root)) return;
            try out.append(allocator, .{
                .name = store_share_name,
                .host_path = root,
                .writable = false,
            });
            return;
        }
    }

    // A share is a directory, so a bind of one file offers the directory it is
    // in. A path this cannot stat is left out: `translate` then refuses and names
    // it, which says more than an offer of a parent nobody asked for.
    const stat = std.Io.Dir.cwd().statFile(io, source, .{}) catch return;
    const directory = if (stat.kind == .directory) source else std.fs.path.dirname(source) orelse return;

    // An offer of the same writability that already holds it covers it. A
    // writable one inside a read only offer is added, because the alternative is
    // making the parent writable.
    for (out.items) |had| {
        if (!underneath(directory, had.host_path)) continue;
        if (had.writable or !writes) return;
    }

    try out.append(allocator, .{
        .name = try nameFor(allocator, out.items, directory),
        .host_path = directory,
        .writable = writes,
    });
}

/// A name for a directory that no other offer has taken. The basename where it
/// reads as one, so a rewritten path in a mount error still says where it came
/// from, and a number after it when two directories share a basename.
pub fn nameFor(
    allocator: std.mem.Allocator,
    taken: []const Share,
    directory: []const u8,
) std.mem.Allocator.Error![]const u8 {
    var buffer: [64]u8 = undefined;
    var len: usize = 0;
    for (std.fs.path.basename(directory)) |byte| {
        if (len == buffer.len) break;
        buffer[len] = switch (byte) {
            'A'...'Z' => byte + 32,
            'a'...'z', '0'...'9' => byte,
            else => '-',
        };
        len += 1;
    }
    const base = if (len == 0) "share" else std.mem.trim(u8, buffer[0..len], "-");
    const wanted = if (base.len == 0) "share" else base;

    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        const name = if (attempt == 0)
            try allocator.dupe(u8, wanted)
        else
            try std.fmt.allocPrint(allocator, "{s}-{d}", .{ wanted, attempt });
        var clash = false;
        for (taken) |had| {
            if (std.mem.eql(u8, had.name, name)) clash = true;
        }
        if (!clash) return name;
        allocator.free(name);
    }
}

/// `config` with every host path rewritten to where the guest sees it.
///
/// The targets are untouched: a path inside the sandbox means the same thing in a
/// guest, which is what keeps a compiler message's path one the user can open.
///
/// **An error and not a null**, so the array this allocates is freed on the way
/// out rather than left behind by a refusal.
///
/// **Give it an arena.** Every rewritten path is its own allocation, and freeing
/// them one at a time means walking the mounts again and knowing which kind each
/// was. `instructions.load` is held the same way for the same reason.
pub fn translate(
    allocator: std.mem.Allocator,
    config: iface.Config,
    set: Set,
    fault: *?Fault,
) Error!iface.Config {
    const mounts = try allocator.alloc(namespace.Mount, config.mounts.len);
    errdefer allocator.free(mounts);

    for (config.mounts, mounts) |from, *into| switch (from) {
        .bind => |one| into.* = .{ .bind = .{
            .source = try place(allocator, set, one.source, !one.read_only, fault),
            .target = one.target,
            .read_only = one.read_only,
        } },
        // The lower layer is only ever read; the upper layer and the work
        // directory are written by overlayfs itself, whatever the mount says.
        .overlay => |one| into.* = .{ .overlay = .{
            .lower = try place(allocator, set, one.lower, false, fault),
            .upper = try place(allocator, set, one.upper, true, fault),
            .work = try place(allocator, set, one.work, true, fault),
            .target = one.target,
        } },
        // Neither names a path of the host's: a procfs is made in the guest, and a
        // denied file is named where it is inside the sandbox.
        .proc, .deny => into.* = from,
    };

    var moved = config;
    moved.mounts = mounts;
    return moved;
}

fn place(
    allocator: std.mem.Allocator,
    set: Set,
    host_path: []const u8,
    writes: bool,
    fault: *?Fault,
) Error![]const u8 {
    if (isGuestDevice(host_path)) return host_path;
    if (underneath(host_path, "/dev")) {
        fault.* = .{ .host_device = host_path };
        return error.NotPlaceable;
    }

    const share = set.holding(host_path) orelse {
        fault.* = .{ .not_offered = host_path };
        return error.NotPlaceable;
    };
    if (writes and !share.writable) {
        fault.* = .{ .needs_writing = host_path };
        return error.NotPlaceable;
    }
    return (try set.insideOf(allocator, host_path)).?;
}

/// Whether `path` is `root` itself or something under it. A prefix alone is not
/// enough: `/worktree` starts with `/work` and is not in it.
pub fn underneath(path: []const u8, root: []const u8) bool {
    if (root.len == 0) return false;
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (path.len == root.len) return true;
    // A root spelled with a trailing slash already ends at a boundary.
    if (root[root.len - 1] == '/') return true;
    return path[root.len] == '/';
}

const testing = std.testing;

const three = Set{
    .root = "/mnt/shares",
    .shares = &.{
        .{ .name = "store", .host_path = "/nix/store", .writable = false },
        .{ .name = "workspace", .host_path = "/var/chock/work", .writable = true },
        .{ .name = "cache", .host_path = "/var/chock/cache", .writable = true },
    },
};

test "a host path becomes the path the guest sees, and the share root itself has no tail" {
    const gpa = testing.allocator;

    const store = (try three.insideOf(gpa, "/nix/store")).?;
    defer gpa.free(store);
    try testing.expectEqualStrings("/mnt/shares/store", store);

    const one = (try three.insideOf(gpa, "/nix/store/aaa-jq/bin/jq")).?;
    defer gpa.free(one);
    try testing.expectEqualStrings("/mnt/shares/store/aaa-jq/bin/jq", one);

    const work = (try three.insideOf(gpa, "/var/chock/work/project")).?;
    defer gpa.free(work);
    try testing.expectEqualStrings("/mnt/shares/workspace/project", work);

    try testing.expectEqual(@as(?[]const u8, null), try three.insideOf(gpa, "/home/ross/.ssh"));
}

test "a prefix is not containment, so a sibling name is not in the share" {
    // `/var/chock/workspace` starts with `/var/chock/work` and is a different
    // directory. Answering the share would put it under the wrong name.
    try testing.expect(three.holding("/var/chock/workspace") == null);
    try testing.expect(three.holding("/var/chock/work") != null);
    try testing.expect(three.holding("/var/chock/work/a") != null);
}

test "the longest share wins, so a nested one keeps its own writability" {
    const nested = Set{
        .root = "/mnt/shares",
        .shares = &.{
            .{ .name = "work", .host_path = "/work", .writable = true },
            .{ .name = "git", .host_path = "/work/.git", .writable = false },
        },
    };

    try testing.expectEqualStrings("git", nested.holding("/work/.git/HEAD").?.name);
    try testing.expectEqualStrings("work", nested.holding("/work/src/main.zig").?.name);
    // And the nested one's writability is what a write is checked against.
    try testing.expect(!nested.holding("/work/.git").?.writable);
}

test "every host path of a config is rewritten, and a target is left alone" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const config = iface.Config{
        .root = "/sandbox",
        .mounts = &.{
            .{ .bind = .{
                .source = "/nix/store/aaa-jq",
                .target = "/nix/store/aaa-jq",
                .read_only = true,
            } },
            .{ .bind = .{ .source = "/var/chock/work/p", .target = "/project" } },
            .{ .proc = .{ .target = "/proc" } },
            .{ .deny = .{ .target = "/project/.env" } },
        },
        .rules = &.{},
        .cwd = "/project",
        .env = &.{},
    };

    var fault: ?Fault = null;
    const moved = try translate(arena, config, three, &fault);
    try testing.expectEqual(@as(?Fault, null), fault);

    try testing.expectEqualStrings("/mnt/shares/store/aaa-jq", moved.mounts[0].bind.source);
    // **The target is what a compiler message prints**, so it is untouched.
    try testing.expectEqualStrings("/nix/store/aaa-jq", moved.mounts[0].bind.target);
    try testing.expectEqualStrings("/mnt/shares/workspace/p", moved.mounts[1].bind.source);
    try testing.expectEqualStrings("/project", moved.mounts[1].bind.target);
    try testing.expectEqualStrings("/proc", moved.mounts[2].proc.target);
    try testing.expectEqualStrings("/project/.env", moved.mounts[3].deny.target);

    // Everything that is not a mount is carried through untouched.
    try testing.expectEqualStrings(config.root, moved.root);
    try testing.expectEqualStrings(config.cwd, moved.cwd);
}

test "a path nothing offers is refused by name, and never left as it was" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const config = iface.Config{
        .root = "/sandbox",
        .mounts = &.{.{ .bind = .{ .source = "/home/ross/.ssh", .target = "/keys" } }},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    };

    var fault: ?Fault = null;
    try testing.expectError(error.NotPlaceable, translate(arena, config, three, &fault));
    try testing.expectEqualStrings("/home/ross/.ssh", fault.?.not_offered);
}

test "a mount that writes into a read only share is refused rather than run" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Writable, and the store is offered read only. Running it would fail inside
    // the tool call as a permission error nobody could trace back to here.
    const config = iface.Config{
        .root = "/sandbox",
        .mounts = &.{.{ .bind = .{
            .source = "/nix/store/aaa-out",
            .target = "/out",
            .read_only = false,
        } }},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    };

    var fault: ?Fault = null;
    try testing.expectError(error.NotPlaceable, translate(arena, config, three, &fault));
    try testing.expectEqualStrings("/nix/store/aaa-out", fault.?.needs_writing);
    try testing.expect(std.mem.indexOf(u8, fault.?.sentence(), "read only") != null);
}

test "an overlay's upper and work must be writable even when the mount does not say so" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // overlayfs writes to both whatever the caller asked for, so a read only
    // share for either is a mount that cannot come up.
    const config = iface.Config{
        .root = "/sandbox",
        .mounts = &.{.{ .overlay = .{
            .lower = "/nix/store/aaa-lower",
            .upper = "/nix/store/aaa-upper",
            .work = "/var/chock/work/w",
            .target = "/project",
        } }},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    };

    var fault: ?Fault = null;
    try testing.expectError(error.NotPlaceable, translate(arena, config, three, &fault));
    try testing.expectEqualStrings("/nix/store/aaa-upper", fault.?.needs_writing);

    // The same overlay with both writable places goes through, and the lower
    // layer stays in the read only share.
    const fixed = iface.Config{
        .root = "/sandbox",
        .mounts = &.{.{ .overlay = .{
            .lower = "/nix/store/aaa-lower",
            .upper = "/var/chock/work/upper",
            .work = "/var/chock/work/w",
            .target = "/project",
        } }},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    };
    var second: ?Fault = null;
    const moved = try translate(arena, fixed, three, &second);
    try testing.expectEqual(@as(?Fault, null), second);
    try testing.expectEqualStrings("/mnt/shares/store/aaa-lower", moved.mounts[0].overlay.lower);
    try testing.expectEqualStrings("/mnt/shares/workspace/upper", moved.mounts[0].overlay.upper);
}

test "the offers cover every path a worktree config binds, and the store folds into one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const base = path_buffer[0..try tmp.dir.realPath(testing.io, &path_buffer)];

    try tmp.dir.createDirPath(testing.io, "repo/.git");
    try tmp.dir.createDirPath(testing.io, "work");
    try tmp.dir.createDirPath(testing.io, "state/objects");
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "repo/.git/commondir", .data = "x" });

    const work = try std.fs.path.join(arena, &.{ base, "work" });
    const git = try std.fs.path.join(arena, &.{ base, "repo/.git" });
    const objects = try std.fs.path.join(arena, &.{ base, "state/objects" });
    const commondir = try std.fs.path.join(arena, &.{ base, "repo/.git/commondir" });

    const config = iface.Config{
        .root = "/sandbox",
        .cwd = "/",
        .rules = &.{},
        .env = &.{},
        .mounts = &.{
            .{ .bind = .{ .source = work, .target = "/work", .read_only = false } },
            .{ .bind = .{ .source = git, .target = "/work/.git", .read_only = true } },
            .{ .bind = .{ .source = objects, .target = "/objects", .read_only = false } },
            // A file, so the directory holding it is what is offered.
            .{ .bind = .{ .source = commondir, .target = "/work/.git/commondir", .read_only = true } },
            // Two store paths of thousands, and one offer between them.
            .{ .bind = .{ .source = "/nix/store/aaa-jq/bin/jq", .target = "/bin/jq", .read_only = true } },
            .{ .bind = .{ .source = "/nix/store/bbb-git", .target = "/git", .read_only = true } },
            .{ .proc = .{ .target = "/proc" } },
        },
    };

    const offers = try offersFor(arena, testing.io, config, &.{}, "/nix/store");
    const set = Set{ .root = "/mnt/shares", .shares = offers };

    // The store is one offer whatever the closure holds, and the file's own
    // directory is already the git offer.
    try testing.expectEqual(@as(usize, 4), offers.len);
    try testing.expectEqualStrings(store_share_name, set.holding("/nix/store/ccc-zig").?.name);
    try testing.expectEqualStrings(git, set.holding(commondir).?.host_path);

    // And the whole point: every source the config names can now be placed.
    var fault: ?Fault = null;
    _ = try translate(arena, config, set, &fault);
    try testing.expectEqual(@as(?Fault, null), fault);
}

test "a writable directory inside a read only one is its own offer" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const base = path_buffer[0..try tmp.dir.realPath(testing.io, &path_buffer)];

    try tmp.dir.createDirPath(testing.io, "git/chock-objects");
    const git = try std.fs.path.join(arena, &.{ base, "git" });
    const objects = try std.fs.path.join(arena, &.{ base, "git/chock-objects" });

    const config = iface.Config{
        .root = "/sandbox",
        .cwd = "/",
        .rules = &.{},
        .env = &.{},
        .mounts = &.{
            .{ .bind = .{ .source = git, .target = "/g", .read_only = true } },
            .{ .bind = .{ .source = objects, .target = "/o", .read_only = false } },
        },
    };

    const offers = try offersFor(arena, testing.io, config, &.{}, null);
    try testing.expectEqual(@as(usize, 2), offers.len);

    // The parent stays read only. Widening it to save a name would give the
    // guest's kernel the whole repository to write.
    const set = Set{ .root = "/mnt/shares", .shares = offers };
    try testing.expect(!set.holding(git).?.writable);
    try testing.expect(set.holding(objects).?.writable);
}

test "two directories with one basename get names of their own" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const base = path_buffer[0..try tmp.dir.realPath(testing.io, &path_buffer)];

    try tmp.dir.createDirPath(testing.io, "one/build");
    try tmp.dir.createDirPath(testing.io, "two/build");
    const first = try std.fs.path.join(arena, &.{ base, "one/build" });
    const second = try std.fs.path.join(arena, &.{ base, "two/build" });

    const config = iface.Config{
        .root = "/sandbox",
        .cwd = "/",
        .rules = &.{},
        .env = &.{},
        .mounts = &.{
            .{ .bind = .{ .source = first, .target = "/a", .read_only = true } },
            .{ .bind = .{ .source = second, .target = "/b", .read_only = true } },
        },
    };

    const offers = try offersFor(arena, testing.io, config, &.{}, null);
    try testing.expectEqual(@as(usize, 2), offers.len);
    try testing.expectEqualStrings("build", offers[0].name);
    try testing.expectEqualStrings("build-1", offers[1].name);
}

test "the store is offered to a session whose own config binds nothing in it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const base = path_buffer[0..try tmp.dir.realPath(testing.io, &path_buffer)];

    try tmp.dir.createDirPath(testing.io, "store");
    try tmp.dir.createDirPath(testing.io, "work");
    const store = try std.fs.path.join(arena, &.{ base, "store" });
    const work = try std.fs.path.join(arena, &.{ base, "work" });

    const config = iface.Config{
        .root = "/sandbox",
        .cwd = "/",
        .rules = &.{},
        .env = &.{},
        .mounts = &.{
            .{ .bind = .{ .source = work, .target = "/work", .read_only = false } },
        },
    };

    // The closure a tool call binds is not in this config, so a set derived from
    // it alone would leave every one of those paths unplaceable.
    const offers = try offersFor(arena, testing.io, config, &.{}, store);
    const set = Set{ .root = "/mnt/shares", .shares = offers };

    const one_of_thousands = try std.fs.path.join(arena, &.{ store, "aaa-libmpc-1.4.1" });
    try testing.expectEqualStrings(store_share_name, set.holding(one_of_thousands).?.name);
    try testing.expect(!set.holding(one_of_thousands).?.writable);
}

test "a store root that is not there is offered to nobody" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const config = iface.Config{
        .root = "/sandbox",
        .cwd = "/",
        .rules = &.{},
        .env = &.{},
        .mounts = &.{},
    };

    const offers = try offersFor(arena, testing.io, config, &.{}, "/no/store/on/this/machine");
    try testing.expectEqual(@as(usize, 0), offers.len);
}

test "a device node every kernel makes crosses as it is, and another is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var config = plainConfig;
    config.mounts = &.{
        .{ .bind = .{ .source = "/dev/null", .target = "/dev/null", .read_only = false } },
    };

    // No offer is made for it, and the source is untouched: the guest's own
    // devtmpfs holds the same device.
    const offers = try offersFor(arena, testing.io, config, &.{}, null);
    try testing.expectEqual(@as(usize, 0), offers.len);

    var fault: ?Fault = null;
    const moved = try translate(arena, config, .{ .root = "/mnt/shares", .shares = offers }, &fault);
    try testing.expectEqual(@as(?Fault, null), fault);
    try testing.expectEqualStrings("/dev/null", moved.mounts[0].bind.source);

    // A device this host has and a guest does not is named rather than placed
    // somewhere it would fail for another reason.
    var passthrough = plainConfig;
    passthrough.mounts = &.{
        .{ .bind = .{ .source = "/dev/ttyUSB0", .target = "/dev/ttyUSB0", .read_only = false } },
    };
    try testing.expectError(
        error.NotPlaceable,
        translate(arena, passthrough, .{ .root = "/mnt/shares", .shares = offers }, &fault),
    );
    try testing.expectEqualStrings("/dev/ttyUSB0", fault.?.host_device);
}

const plainConfig = iface.Config{
    .root = "/sandbox",
    .cwd = "/",
    .rules = &.{},
    .env = &.{},
    .mounts = &.{},
};
