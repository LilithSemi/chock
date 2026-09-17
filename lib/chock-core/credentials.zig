//! What one approved act may reach that no other tool call may: a directory of
//! sockets, and one helper program, bound into the sandbox for the length of
//! that act and gone after it.
//!
//! ## Why this is a seam and not a call
//!
//! `chock-core` imports no `chock-broker`, so this library does not know what
//! an askpass socket is, what an ssh agent is, or what a git remote looks
//! like. What it knows is how to build a tool call's sandbox. So the caller
//! that holds all of that, `src/run.zig`, answers a `Grant` and this library
//! turns it into two mounts, two Landlock rules and a few environment
//! entries. It is the same shape `tools.Context.net` already keeps for the
//! network broker, and for the same reason.
//!
//! ## The lifetime is the whole of the security property
//!
//! `grant` is asked once per tool call, right before that call's own sandbox
//! is built. A caller answers null for every call but the one act a person
//! approved, so the capability exists during that act and at no other time.
//! `lib/chock-broker/agentproxy.zig` says at length why that matters: a
//! proxied ssh agent can sign anything at all while it is reachable, and no
//! proxy can tell one signature from another by reading the bytes, so scope is
//! the only defence there is.
//!
//! ## Measured, and this is why the shape is two mounts and not one
//!
//! The helper is a second **top level** mount and never a file nested inside
//! the socket directory's mount. A nested bind needs to open its target for
//! writing, and a read only mount refuses that with `EROFS`, so a nested
//! helper forces the socket directory to be mounted writable. Measured on this
//! machine, both ways:
//!
//! ```
//! socket dir read only, helper nested   the mount tree fails to build
//! socket dir writable,  helper nested   works, writes refused by Landlock
//! socket dir read only, helper separate works, writes refused by the mount
//! ```
//!
//! The third is what this builds. A sandboxed program that tries to create a
//! file beside the socket, or to unlink the socket, gets `EROFS` from the
//! mount itself, so the refusal does not depend on Landlock being available on
//! the machine, and the Landlock rule is then the second layer rather than the
//! only one.
//!
//! ## The sandbox may connect, and may do nothing else
//!
//! It cannot write in the directory, cannot replace the socket, and cannot
//! read a credential out of it, because there is no credential there to read:
//! a socket is not a file with a value in it. What is on the far side of that
//! socket is another process, which decides for itself what to answer.

const std = @import("std");
const sandbox = @import("chock-sandbox");

const idle_mod = @import("idle.zig");

/// Where the socket directory of an approved act appears inside the sandbox.
///
/// Under `/run/chock`, which `lib/chock-sandbox/Sandbox.zig` names
/// `runtime_prefix` and keeps for Chock's own paths, so the project keeps the
/// root to itself. Written out here, the way `cache.zig` writes out its own,
/// because this library states the path and the sandbox library only carries
/// it.
pub const sandbox_dir = "/run/chock/credentials";

/// Where the helper program appears inside the sandbox.
///
/// **A directory of its own, and not a file inside `sandbox_dir`.** See this
/// file's own top comment for the measurement behind that.
pub const helper_dir = "/run/chock/helper";

/// Where a socket directory that lives at `host_dir` appears inside the
/// sandbox.
///
/// **Two answers, one per platform**, exactly as `cache.sandboxDirFor` gives
/// two. A build that moves a path puts the directory at `sandbox_dir`, so the
/// path is the same in every session. macOS moves no path, so the directory
/// appears where it really is and the mount becomes a rule.
pub fn sandboxDirFor(host_dir: []const u8) []const u8 {
    return if (sandbox.expresses.moved_paths) sandbox_dir else host_dir;
}

/// Where a helper program that lives at `host_path` appears inside the
/// sandbox. `name` is the file name it must be invoked as, which is what
/// selects the command a multi-call binary runs: see
/// `lib/chock-broker/askpass.zig`'s own `link_name`.
///
/// The caller owns the answer.
pub fn helperPathFor(
    allocator: std.mem.Allocator,
    host_path: []const u8,
    name: []const u8,
) std.mem.Allocator.Error![]u8 {
    if (!sandbox.expresses.moved_paths) return allocator.dupe(u8, host_path);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ helper_dir, name });
}

/// What one approved act needs bound into its sandbox.
///
/// **Every string is borrowed and the caller keeps them alive for the whole
/// call.** That is the same borrowing `tools.Context` already asks of every
/// path in it.
///
/// **There is no field here a credential could sit in, and there must never
/// be one.** A value travels on a socket and never through a mount tree or an
/// environment entry: see `lib/chock-broker/askpass.zig`'s own top comment,
/// and the comptime block at the end of this file, which fails the build if
/// such a field appears.
pub const Grant = struct {
    /// The directory on the host holding this act's sockets. Bound read only.
    host_dir: []const u8,
    /// The helper program on the host, or null for an act that needs none.
    helper_source: ?[]const u8 = null,
    /// The file name the helper must be invoked as. Read only when
    /// `helper_source` is set.
    helper_name: []const u8 = "",
    /// `KEY=VALUE` entries to add to the call's environment, already spelled
    /// for the paths inside the sandbox. An entry whose key is already in the
    /// environment replaces it.
    ///
    /// **A path and never a value.** See this type's own comment.
    env: []const []const u8 = &.{},
};

/// The seam itself.
pub const Seam = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// What this tool call may reach, or null for one that may reach
        /// nothing. Asked once per call, right before the sandbox is built.
        grant: *const fn (ptr: *anyopaque, tool: []const u8, call_id: []const u8) ?Grant,
        /// One look at whatever is listening on those sockets. Driven from
        /// `idle.Idle` while the sandboxed program runs, so it **may not
        /// append to the session log**: see `lib/chock-core/idle.zig`.
        step: *const fn (ptr: *anyopaque) void,
    };

    pub fn grant(self: Seam, tool: []const u8, call_id: []const u8) ?Grant {
        return self.vtable.grant(self.ptr, tool, call_id);
    }

    pub fn step(self: Seam) void {
        self.vtable.step(self.ptr);
    }
};

/// An `Idle` that serves the sockets of an armed act and then does whatever
/// the caller was already doing.
///
/// **Both, and in this order.** The sockets first, because a program inside
/// the sandbox is blocked on one of them and the display is not blocked on
/// anything. A caller with no display of its own still gets one of these, and
/// that is the point: without it a piped `chock run` would never serve the
/// socket at all, and `git` would wait for a prompt nobody was listening for
/// until the call's own deadline.
///
/// **Built in place and never copied**, the rule every seam in this library
/// carries.
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

/// Everything one armed act owns for the length of one tool call.
///
/// **A type with a `deinit`, and not a bare slice, because a mount borrows its
/// target.** The helper's path inside the sandbox is built here, and both the
/// mount and the Landlock rule point at those bytes for as long as the call
/// runs. Freeing it when `arm` returned would leave the mount tree naming
/// memory that had gone, which is exactly the fault the first version of this
/// function shipped with and which its own test caught.
pub const Armed = struct {
    /// The call's environment, every entry owned.
    env: []const []const u8,
    /// The helper's path inside the sandbox, borrowed by one mount and one
    /// rule. Null for an act with no helper.
    helper_path: ?[]u8 = null,

    pub fn deinit(self: *Armed, allocator: std.mem.Allocator) void {
        freeEnvironment(allocator, self.env);
        if (self.helper_path) |path| allocator.free(path);
        self.* = undefined;
    }
};

/// The mounts, the Landlock rules and the environment one `Grant` comes to.
///
/// `mounts` and `rules` are appended to the lists the caller already holds,
/// which is how every other per call surface in `tools.runCommand` is built.
/// The caller owns the answer and ends it with `Armed.deinit`, **after the
/// call has finished**, because the mount tree borrows from it.
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
        // A helper is a file and not a directory, so its rule cannot carry
        // `read_only`'s directory bits: `landlock_add_rule` answers `EINVAL`
        // for a directory only right on a path that is not one.
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

/// Free what `arm` or `environment` answered. Every entry is owned, so this
/// frees every entry and then the slice. The same spelling
/// `chock_core.cache.freeEnvironment` has, so a caller holding both results
/// frees them the same way.
pub fn freeEnvironment(allocator: std.mem.Allocator, entries: []const []const u8) void {
    for (entries) |entry| allocator.free(entry);
    allocator.free(entries);
}

/// `base` with every entry of `extra` added, replacing any entry of `base`
/// that names the same key.
///
/// **Replacing and never appending twice.** A dev shell states `SSH_AUTH_SOCK`
/// often enough, and a second entry with the same key is read by some programs
/// and not by others, so a call that ended up with both would work or not work
/// depending on which program the agent ran.
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

/// True when this `KEY=VALUE` entry has the same key as one of `extra`.
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

// A grant names paths. **It holds no credential and it must not grow a field
// one could sit in**, because a mount tree and an environment are both visible
// to anything that can read `/proc`, and the whole design puts the value on a
// socket for exactly that reason. This fails the build if such a field
// appears.
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
    // **The fault this closes.** A dev shell states `SSH_AUTH_SOCK` on a
    // machine with an agent running, and an environment holding both that one
    // and the proxy's would point some programs at the host's own agent, which
    // the sandbox cannot reach, and others at the proxy. Which one won would
    // depend on the program.
    //
    // Mutation check: drop the `namedIn` guard from the first loop of
    // `environment` and the count below is 4 rather than 3.
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

    // An entry with no `=` in it is not a variable, and it is kept rather than
    // read as one with an empty name.
    const odd = [_][]const u8{ "PATH=/bin", "not-a-variable" };
    const kept = try environment(gpa, &odd, &extra);
    defer freeEnvironment(gpa, kept);
    try testing.expectEqual(@as(usize, 3), kept.len);
}

test "a grant becomes two mounts and two rules, and the socket directory is read only" {
    // The shape this file's own top comment measured. The socket directory is
    // bound read only, so a sandboxed program that tries to replace the socket
    // is refused by the mount and not only by Landlock.
    //
    // Mutation check: set `.read_only = false` on the first mount below and
    // the third expectation fails.
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

    // **The helper is a top level target and never nested inside the socket
    // directory's own mount**, which is what lets that mount be read only.
    //
    // Mutation check: make `helperPathFor` answer a path under `sandbox_dir`
    // and this fails.
    try testing.expect(!std.mem.startsWith(u8, mounts.items[1].bind.target, sandboxDirFor("/session/abc.cred")));

    // A file cannot carry a directory only right, which the kernel answers
    // `EINVAL` for.
    try testing.expect(rules.items[1].access.execute);
    try testing.expect(!rules.items[1].access.read_dir);

    try testing.expectEqual(@as(usize, 2), armed.env.len);

    // **The mount target is still readable after `arm` returned.** The first
    // version of this function freed the helper path before returning, and the
    // mount tree then named memory that had gone. This is what caught it.
    try testing.expectEqualStrings(armed.helper_path.?, mounts.items[1].bind.target);
    // **Both platforms asserted, because both behaviours are deliberate.**
    // `helperPathFor` puts the helper at `<helper_dir>/<name>` where a build
    // moves paths, so the target ends in the name that selects the command a
    // multi-call binary runs. macOS moves no path, so the helper appears where
    // it really is and the target is the source verbatim. This test asserted
    // only the first and so failed on the CI Mac.
    if (sandbox.expresses.moved_paths) {
        try testing.expect(std.mem.endsWith(u8, mounts.items[1].bind.target, "/askpass"));
    } else {
        try testing.expectEqualStrings("/usr/bin/chock", mounts.items[1].bind.target);
    }

    // An act with no helper is one mount and one rule, and owns no path.
    mounts.clearRetainingCapacity();
    rules.clearRetainingCapacity();
    var bare = try arm(gpa, .{ .host_dir = "/session/abc.cred" }, &.{}, &mounts, &rules);
    defer bare.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), mounts.items.len);
    try testing.expectEqual(@as(usize, 1), rules.items.len);
    try testing.expectEqual(@as(?[]u8, null), bare.helper_path);
}

test "the chain serves the sockets first and then the caller's own look" {
    // A program inside the sandbox is blocked on the socket. The display is
    // blocked on nothing. So the sockets go first.
    //
    // Mutation check: swap the two lines of `Chain.stepFn` and the order
    // recorded below reverses.
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

    // **A caller with no display of its own still serves the sockets.**
    // Without this, a piped `chock run` would never answer a prompt at all.
    var alone = Chain{ .seam = .{ .ptr = &recorder, .vtable = &seam_vtable } };
    alone.idle().step();
    try testing.expectEqual(@as(u8, 's'), recorder.order[2]);
    try testing.expectEqual(@as(usize, 3), recorder.at);
}
