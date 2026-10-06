//! What one approved act may reach that no other tool call may: a
//! directory of sockets and one helper program, bound into the sandbox
//! for the length of that act and gone after it.

const std = @import("std");
const sandbox = @import("chock-sandbox");

const idle_mod = @import("idle.zig");

pub const sandbox_dir = "/run/chock/credentials";

pub const helper_dir = "/run/chock/helper";

pub fn sandboxDirFor(host_dir: []const u8) []const u8 {
    return if (sandbox.expresses.moved_paths) sandbox_dir else host_dir;
}

pub fn helperPathFor(
    allocator: std.mem.Allocator,
    host_path: []const u8,
    name: []const u8,
) std.mem.Allocator.Error![]u8 {
    if (!sandbox.expresses.moved_paths) return allocator.dupe(u8, host_path);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ helper_dir, name });
}

pub const Grant = struct {
    host_dir: []const u8,
    helper_source: ?[]const u8 = null,
    helper_name: []const u8 = "",
    env: []const []const u8 = &.{},
};

pub const Seam = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        grant: *const fn (ptr: *anyopaque, tool: []const u8, call_id: []const u8) ?Grant,
        step: *const fn (ptr: *anyopaque) void,
    };

    pub fn grant(self: Seam, tool: []const u8, call_id: []const u8) ?Grant {
        return self.vtable.grant(self.ptr, tool, call_id);
    }

    pub fn step(self: Seam) void {
        self.vtable.step(self.ptr);
    }
};

pub const Chain = struct {
    seam: ?Seam = null,
    inner: ?idle_mod.Idle = null,

    pub fn idle(self: *Chain) idle_mod.Idle {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = idle_mod.Idle.VTable{ .step = stepFn };

    fn stepFn(ptr: *anyopaque) void {
        const self: *Chain = @ptrCast(@alignCast(ptr));
        if (self.seam) |one| one.step();
        if (self.inner) |one| one.step();
    }
};

pub const Armed = struct {
    env: []const []const u8,
    helper_path: ?[]u8 = null,

    pub fn deinit(self: *Armed, allocator: std.mem.Allocator) void {
        freeEnvironment(allocator, self.env);
        if (self.helper_path) |path| allocator.free(path);
        self.* = undefined;
    }
};

pub fn arm(
    allocator: std.mem.Allocator,
    granted: Grant,
    base_env: []const []const u8,
    mounts: *std.ArrayList(sandbox.namespace.Mount),
    rules: *std.ArrayList(sandbox.Config.Rule),
) std.mem.Allocator.Error!Armed {
    const inside = sandboxDirFor(granted.host_dir);
    try mounts.append(allocator, .{ .bind = .{
        .source = granted.host_dir,
        .target = inside,
        .read_only = true,
    } });
    try rules.append(allocator, .{
        .path = inside,
        .access = sandbox.landlock.AccessFs.read_only,
    });

    var helper_path: ?[]u8 = null;
    errdefer if (helper_path) |path| allocator.free(path);

    if (granted.helper_source) |source| {
        helper_path = try helperPathFor(allocator, source, granted.helper_name);
        try mounts.append(allocator, .{ .bind = .{
            .source = source,
            .target = helper_path.?,
            .read_only = true,
        } });
        try rules.append(allocator, .{
            .path = helper_path.?,
            .access = .{ .execute = true, .read_file = true },
        });
    }

    return .{
        .env = try environment(allocator, base_env, granted.env),
        .helper_path = helper_path,
    };
}

pub fn freeEnvironment(allocator: std.mem.Allocator, entries: []const []const u8) void {
    for (entries) |entry| allocator.free(entry);
    allocator.free(entries);
}

pub fn environment(
    allocator: std.mem.Allocator,
    base: []const []const u8,
    extra: []const []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var entries: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (entries.items) |entry| allocator.free(entry);
        entries.deinit(allocator);
    }

    for (base) |entry| {
        if (namedIn(entry, extra)) continue;
        try entries.append(allocator, try allocator.dupe(u8, entry));
    }
    for (extra) |entry| {
        try entries.append(allocator, try allocator.dupe(u8, entry));
    }
    return entries.toOwnedSlice(allocator);
}

fn namedIn(entry: []const u8, extra: []const []const u8) bool {
    const key = keyOf(entry);
    if (key.len == 0) return false;
    for (extra) |one| {
        if (std.mem.eql(u8, key, keyOf(one))) return true;
    }
    return false;
}

fn keyOf(entry: []const u8) []const u8 {
    const at = std.mem.indexOfScalar(u8, entry, '=') orelse return "";
    return entry[0..at];
}

comptime {
    for (@typeInfo(Grant).@"struct".fields) |field| {
        const name = field.name;
        if (std.mem.indexOf(u8, name, "secret") != null or
            std.mem.indexOf(u8, name, "password") != null or
            std.mem.indexOf(u8, name, "token") != null or
            std.mem.indexOf(u8, name, "key") != null)
        {
            @compileError("credentials.Grant must hold no credential: remove the field " ++ name ++
                ". A value travels on a socket, never through a mount tree or an environment.");
        }
    }
}

const testing = std.testing;

test "an entry of the call's own environment replaces one of the same name" {
    const gpa = testing.allocator;

    const base = [_][]const u8{ "PATH=/bin", "SSH_AUTH_SOCK=/host/agent", "TERM=dumb" };
    const extra = [_][]const u8{"SSH_AUTH_SOCK=/run/chock/credentials/a"};

    const built = try environment(gpa, &base, &extra);
    defer freeEnvironment(gpa, built);

    try testing.expectEqual(@as(usize, 3), built.len);
    var found: usize = 0;
    for (built) |entry| {
        if (std.mem.startsWith(u8, entry, "SSH_AUTH_SOCK=")) {
            found += 1;
            try testing.expectEqualStrings("SSH_AUTH_SOCK=/run/chock/credentials/a", entry);
        }
    }
    try testing.expectEqual(@as(usize, 1), found);

    const odd = [_][]const u8{ "PATH=/bin", "not-a-variable" };
    const kept = try environment(gpa, &odd, &extra);
    defer freeEnvironment(gpa, kept);
    try testing.expectEqual(@as(usize, 3), kept.len);
}

test "a grant becomes two mounts and two rules, and the socket directory is read only" {
    const gpa = testing.allocator;

    var mounts: std.ArrayList(sandbox.namespace.Mount) = .empty;
    defer mounts.deinit(gpa);
    var rules: std.ArrayList(sandbox.Config.Rule) = .empty;
    defer rules.deinit(gpa);

    var armed = try arm(gpa, .{
        .host_dir = "/session/abc.cred",
        .helper_source = "/usr/bin/chock",
        .helper_name = "askpass",
        .env = &.{"GIT_ASKPASS=/run/chock/helper/askpass"},
    }, &.{"PATH=/bin"}, &mounts, &rules);
    defer armed.deinit(gpa);

    try testing.expectEqual(@as(usize, 2), mounts.items.len);
    try testing.expectEqual(@as(usize, 2), rules.items.len);
    try testing.expect(mounts.items[0].bind.read_only);
    try testing.expect(mounts.items[1].bind.read_only);
    try testing.expectEqualStrings("/session/abc.cred", mounts.items[0].bind.source);
    try testing.expectEqualStrings("/usr/bin/chock", mounts.items[1].bind.source);

    try testing.expect(!std.mem.startsWith(u8, mounts.items[1].bind.target, sandboxDirFor("/session/abc.cred")));

    try testing.expect(rules.items[1].access.execute);
    try testing.expect(!rules.items[1].access.read_dir);

    try testing.expectEqual(@as(usize, 2), armed.env.len);

    try testing.expectEqualStrings(armed.helper_path.?, mounts.items[1].bind.target);
    if (sandbox.expresses.moved_paths) {
        try testing.expect(std.mem.endsWith(u8, mounts.items[1].bind.target, "/askpass"));
    } else {
        try testing.expectEqualStrings("/usr/bin/chock", mounts.items[1].bind.target);
    }

    mounts.clearRetainingCapacity();
    rules.clearRetainingCapacity();
    var bare = try arm(gpa, .{ .host_dir = "/session/abc.cred" }, &.{}, &mounts, &rules);
    defer bare.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), mounts.items.len);
    try testing.expectEqual(@as(usize, 1), rules.items.len);
    try testing.expectEqual(@as(?[]u8, null), bare.helper_path);
}

test "the chain serves the sockets first and then the caller's own look" {
    const Recorder = struct {
        order: [4]u8 = @splat(0),
        at: usize = 0,

        fn seamStep(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.order[self.at] = 's';
            self.at += 1;
        }
        fn innerStep(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.order[self.at] = 'i';
            self.at += 1;
        }
        fn grantFn(_: *anyopaque, _: []const u8, _: []const u8) ?Grant {
            return null;
        }
    };
    var recorder = Recorder{};

    const seam_vtable = Seam.VTable{ .grant = Recorder.grantFn, .step = Recorder.seamStep };
    const inner_vtable = idle_mod.Idle.VTable{ .step = Recorder.innerStep };

    var chain = Chain{
        .seam = .{ .ptr = &recorder, .vtable = &seam_vtable },
        .inner = .{ .ptr = &recorder, .vtable = &inner_vtable },
    };
    chain.idle().step();
    try testing.expectEqual(@as(u8, 's'), recorder.order[0]);
    try testing.expectEqual(@as(u8, 'i'), recorder.order[1]);

    var alone = Chain{ .seam = .{ .ptr = &recorder, .vtable = &seam_vtable } };
    alone.idle().step();
    try testing.expectEqual(@as(u8, 's'), recorder.order[2]);
    try testing.expectEqual(@as(usize, 3), recorder.at);
}
