//! Where a host path is inside a guest.
//!
//! A guest mounts one virtiofs filesystem, and every directory the host offers
//! appears as a name inside it. So a `Config` built on the host names paths the
//! guest has never heard of: `/nix/store` on this machine is
//! `<root>/store` in there. This module rewrites one into the other.
//!
//! ## The share set is given and never derived
//!
//! `Config.mounts` holds one entry per store path, which is thousands for a real
//! dev shell closure, and a guest takes 32 offers. So the share set is what the
//! session already knows: the store read only, the workspace writable, the cache
//! writable. Deriving it from the mounts would either exceed the bound or merge
//! paths of different writability into one name, and the second is worse than the
//! first.
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

    pub fn path(self: Fault) []const u8 {
        return switch (self) {
            .not_offered, .needs_writing => |one| one,
        };
    }

    pub fn sentence(self: Fault) []const u8 {
        return switch (self) {
            .not_offered => "no directory offered to the guest holds it",
            .needs_writing => "the mount writes there and the directory offered is read only",
        };
    }
};

pub const Error = std.mem.Allocator.Error || error{
    /// A host path could not be placed in the guest. `fault` says which and why.
    NotPlaceable,
};

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
fn underneath(path: []const u8, root: []const u8) bool {
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
