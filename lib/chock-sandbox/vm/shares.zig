//! Converts a host path to its location inside the guest, using the virtiofs share set a
//! Config's mounts build.

const std = @import("std");

const iface = @import("../Sandbox.zig");
const namespace = @import("../linux/namespace.zig");

pub const Share = struct {
    name: []const u8,
    host_path: []const u8,
    writable: bool,
};

pub const Set = struct {
    root: []const u8,
    shares: []const Share,

    pub fn holding(self: Set, host_path: []const u8) ?Share {
        var best: ?Share = null;
        for (self.shares) |one| {
            if (!underneath(host_path, one.host_path)) continue;
            const longer = if (best) |had| one.host_path.len > had.host_path.len else true;
            if (longer) best = one;
        }
        return best;
    }

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

pub const Fault = union(enum) {
    not_offered: []const u8,
    needs_writing: []const u8,
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
    NotPlaceable,
};

pub const max_offers: usize = 32;

pub const store_share_name = "store";

pub const Wanted = struct {
    host_path: []const u8,
    writable: bool,
};

pub const OfferError = std.mem.Allocator.Error || error{
    TooManyOffers,
};

pub fn offersFor(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: iface.Config,
    extra: []const Wanted,
    store_root: ?[]const u8,
) OfferError![]const Share {
    var out: std.ArrayList(Share) = .empty;

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
        .proc, .deny => {},
    };
    for (extra) |one| try offer(allocator, io, &out, one.host_path, one.writable, store_root);

    if (out.items.len > max_offers) return error.TooManyOffers;
    return out.toOwnedSlice(allocator);
}

fn offer(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.ArrayList(Share),
    source: []const u8,
    writes: bool,
    store_root: ?[]const u8,
) std.mem.Allocator.Error!void {
    if (source.len == 0) return;
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

    const stat = std.Io.Dir.cwd().statFile(io, source, .{}) catch return;
    const directory = if (stat.kind == .directory) source else std.fs.path.dirname(source) orelse return;

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
        .overlay => |one| into.* = .{ .overlay = .{
            .lower = try place(allocator, set, one.lower, false, fault),
            .upper = try place(allocator, set, one.upper, true, fault),
            .work = try place(allocator, set, one.work, true, fault),
            .target = one.target,
        } },
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

pub fn underneath(path: []const u8, root: []const u8) bool {
    if (root.len == 0) return false;
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (path.len == root.len) return true;
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
    try testing.expectEqualStrings("/nix/store/aaa-jq", moved.mounts[0].bind.target);
    try testing.expectEqualStrings("/mnt/shares/workspace/p", moved.mounts[1].bind.source);
    try testing.expectEqualStrings("/project", moved.mounts[1].bind.target);
    try testing.expectEqualStrings("/proc", moved.mounts[2].proc.target);
    try testing.expectEqualStrings("/project/.env", moved.mounts[3].deny.target);

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
            .{ .bind = .{ .source = commondir, .target = "/work/.git/commondir", .read_only = true } },
            .{ .bind = .{ .source = "/nix/store/aaa-jq/bin/jq", .target = "/bin/jq", .read_only = true } },
            .{ .bind = .{ .source = "/nix/store/bbb-git", .target = "/git", .read_only = true } },
            .{ .proc = .{ .target = "/proc" } },
        },
    };

    const offers = try offersFor(arena, testing.io, config, &.{}, "/nix/store");
    const set = Set{ .root = "/mnt/shares", .shares = offers };

    try testing.expectEqual(@as(usize, 4), offers.len);
    try testing.expectEqualStrings(store_share_name, set.holding("/nix/store/ccc-zig").?.name);
    try testing.expectEqualStrings(git, set.holding(commondir).?.host_path);

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

    const offers = try offersFor(arena, testing.io, config, &.{}, null);
    try testing.expectEqual(@as(usize, 0), offers.len);

    var fault: ?Fault = null;
    const moved = try translate(arena, config, .{ .root = "/mnt/shares", .shares = offers }, &fault);
    try testing.expectEqual(@as(?Fault, null), fault);
    try testing.expectEqualStrings("/dev/null", moved.mounts[0].bind.source);

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
