//! The eight acts the broker can do, and the one way to ask for one. An
//! approval lets the broker do one act. It does not widen the sandbox.

const std = @import("std");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const chock_version = @import("chock-version");
const chock_workspace = @import("chock-workspace");
const Broker = @import("Broker.zig");
const diagnostic = @import("diagnostic.zig");
const integrate = @import("integrate.zig");
const network = @import("network.zig");
pub const Diagnostic = diagnostic.Diagnostic;

const event = chock_proto.event;
const git = chock_workspace.git;

pub const Kind = enum {
    git_commit,
    git_push,
    git_branch_delete,
    net_fetch,
    nix_build,
    file_write,
    workspace_apply,
    model_select,

    /// `chock-policy` matches a `git.*` prefix on this dotted spelling.
    pub fn wireName(self: Kind) []const u8 {
        return switch (self) {
            .git_commit => "git.commit",
            .git_push => "git.push",
            .git_branch_delete => "git.branch.delete",
            .net_fetch => "net.fetch",
            .nix_build => "nix.build",
            .file_write => "file.write",
            .workspace_apply => "workspace.apply",
            .model_select => "model.select",
        };
    }
};

pub const self_asked_tool = "request_action";

pub const GitCommit = struct {
    repository: []const u8,
    paths: []const []const u8,
    message: []const u8,
    diff: []const u8,
};

pub const GitPush = struct {
    repository: []const u8,
    remote: []const u8,
    remote_url: []const u8,
    remote_ref: []const u8,
    old_id: []const u8,
    new_id: []const u8,
    commits: []const u8,
};

pub const GitBranchDelete = struct {
    repository: []const u8,
    branch: []const u8,
    points_at: []const u8,
    merged_into: []const u8,
};

pub const NetFetch = struct {
    host: []const u8,
    url: []const u8,
    method: Method = .get,
    max_bytes: usize = default_fetch_bytes,

    pub const Method = enum {
        get,
        head,

        pub fn wireName(self: Method) []const u8 {
            return switch (self) {
                .get => "GET",
                .head => "HEAD",
            };
        }
    };
};

pub const NixBuild = struct {
    installable: []const u8,
    /// The sandbox never has this socket, and the broker does.
    daemon_socket: []const u8 = default_nix_daemon_socket,
};

pub const FileWrite = struct {
    path: []const u8,
    workspace_root: []const u8,
    contents: []const u8,
    previous: ?[]const u8 = null,

    pub fn describing(
        arena: std.mem.Allocator,
        io: std.Io,
        params: struct {
            path: []const u8,
            workspace_root: []const u8,
            contents: []const u8,
        },
        diag: ?*?Diagnostic,
    ) DescribeError!FileWrite {
        const previous: ?[]const u8 = if (std.Io.Dir.cwd().readFileAlloc(
            io,
            params.path,
            arena,
            .limited(max_previous_bytes),
        )) |bytes| bytes else |err| switch (err) {
            error.FileNotFound => null,
            error.OutOfMemory => return error.OutOfMemory,
            // A silent empty "what is there now" would read as an empty file.
            error.StreamTooLong => "[more bytes than the broker shows, and every one of them is replaced]",
            else => {
                _ = diagnostic.note(diag, .{ .path_read_failed = .{ .path = params.path, .err = err } });
                return error.Unexpected;
            },
        };

        return .{
            .path = params.path,
            .workspace_root = params.workspace_root,
            .contents = params.contents,
            .previous = previous,
        };
    }
};

pub const max_previous_bytes: usize = 1 << 20;

pub const WorkspaceApply = struct {
    repository: []const u8,
    scratch_object_store: []const u8,
    project_object_store: []const u8,
    ref: []const u8,
    old_id: []const u8,
    new_id: []const u8,
    objects: []const []const u8,
    diff: []const u8,
    /// No default: `chock_policy.apply.Settings` decides where work lands.
    integration: integrate.Plan,
    /// The `workspace` block's copies which land on the user's own files when
    /// this applies. A line of this prompt and never a second question: the
    /// answer given here is the answer to both.
    copies: []const []const u8 = &.{},

    pub fn describing(
        arena: std.mem.Allocator,
        io: std.Io,
        ctx: Context,
        params: struct {
            repository: []const u8,
            scratch_object_store: []const u8,
            ref: []const u8,
            new_id: []const u8,
            wanted: integrate.Wanted,
            copies: []const []const u8 = &.{},
        },
        diag: ?*?Diagnostic,
    ) DescribeError!WorkspaceApply {
        // Read from git: `.git/objects` is wrong for a worktree, a bare
        // repository, and a separate git directory.
        const project_object_store = try describeGit(arena, io, ctx.env, params.repository, &.{
            "rev-parse", "--path-format=absolute", "--git-path", "objects",
        }, diag);

        const old_id = readRef(arena, io, ctx.env, params.repository, params.ref) catch |err| return err;

        // Before the object list is read. A merge, a rebase or a squash builds
        // new commits in the scratch store, and the list below must hold them.
        const integration = try integrate.planning(arena, io, ctx.env, .{
            .repository = params.repository,
            .scratch_object_store = params.scratch_object_store,
            .project_object_store = project_object_store,
            .wanted = params.wanted,
            .ref = params.ref,
            .new_id = params.new_id,
        }, diag);

        const objects = try looseObjects(arena, io, params.scratch_object_store, diag);

        // The scratch store is an alternate here. git never writes to one.
        var reading_env = try ctx.env.clone(arena);
        defer reading_env.deinit();
        try reading_env.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", params.scratch_object_store);

        const diff = if (old_id.len > 0)
            try describeGit(arena, io, &reading_env, params.repository, &.{
                "diff", old_id, params.new_id,
            }, diag)
        else
            try describeGit(arena, io, &reading_env, params.repository, &.{
                "show", "--format=%H%n%s%n", params.new_id,
            }, diag);

        return .{
            .repository = params.repository,
            .scratch_object_store = params.scratch_object_store,
            .project_object_store = project_object_store,
            .ref = params.ref,
            .old_id = old_id,
            .new_id = params.new_id,
            .objects = objects,
            .diff = diff,
            .integration = integration,
            .copies = params.copies,
        };
    }
};

fn describeGit(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    argv: []const []const u8,
    diag: ?*?Diagnostic,
) DescribeError![]u8 {
    var output = try git.run(arena, io, env, cwd, argv, null);
    defer output.deinit(arena);
    const exited_zero = switch (output.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!exited_zero) {
        if (diagnostic.wants(diag)) {
            _ = diagnostic.note(diag, .{ .git_refused_a_description = try arena.dupe(u8, output.stderr) });
        }
        return error.GitFailed;
    }
    return arena.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

fn readRef(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    repository: []const u8,
    ref: []const u8,
) DescribeError![]u8 {
    var output = try git.run(arena, io, env, repository, &.{ "rev-parse", "--verify", "--quiet", ref }, null);
    defer output.deinit(arena);
    return switch (output.term) {
        .exited => |code| if (code == 0)
            arena.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"))
        else
            arena.dupe(u8, ""),
        else => error.GitFailed,
    };
}

/// A pack file refuses the whole description. Only `git gc` writes one, and
/// Chock never runs it, so the loose half is less than the whole of the work.
fn looseObjects(
    arena: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    diag: ?*?Diagnostic,
) DescribeError![]const []const u8 {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true }) catch |err| {
        _ = diagnostic.note(diag, .{ .scratch_store_unreadable = .{ .path = path, .err = err } });
        return error.Unexpected;
    };
    defer dir.close(io);

    var walker = try dir.walk(arena);
    defer walker.deinit();

    var ids: std.ArrayList([]const u8) = .empty;
    while (walker.next(io) catch |err| {
        _ = diagnostic.note(diag, .{ .scratch_store_walk_failed = err });
        return error.Unexpected;
    }) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.startsWith(u8, entry.path, "info" ++ std.fs.path.sep_str)) continue;
        if (std.mem.startsWith(u8, entry.path, "pack" ++ std.fs.path.sep_str)) return error.PackedObjectsFound;

        const id = objectIdOfPath(arena, entry.path) catch |err| switch (err) {
            error.NotAnObject => {
                // `entry.path` belongs to the walker, so this keeps a copy.
                if (diagnostic.wants(diag)) {
                    _ = diagnostic.note(diag, .{
                        .scratch_store_holds_a_non_object = try arena.dupe(u8, entry.path),
                    });
                }
                continue;
            },
            else => |e| return e,
        };
        try ids.append(arena, id);
    }

    const owned = try ids.toOwnedSlice(arena);
    std.mem.sort([]const u8, owned, {}, lessThanBytes);
    return owned;
}

fn lessThanBytes(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn objectIdOfPath(arena: std.mem.Allocator, entry_path: []const u8) (std.mem.Allocator.Error || error{NotAnObject})![]const u8 {
    // Two characters, a separator, and the rest of the id: 41 for a SHA-1
    // name and 65 for a SHA-256 one.
    if (entry_path.len != 41 and entry_path.len != 65) return error.NotAnObject;
    if (entry_path[2] != std.fs.path.sep) return error.NotAnObject;

    const id = try arena.alloc(u8, entry_path.len - 1);
    errdefer arena.free(id);
    @memcpy(id[0..2], entry_path[0..2]);
    @memcpy(id[2..], entry_path[3..]);
    checkObjectId(id) catch {
        arena.free(id);
        return error.NotAnObject;
    };
    return id;
}

pub const ModelSelect = struct {
    from: []const u8,
    to: []const u8,
};

pub const default_fetch_bytes: usize = 8 * 1024 * 1024;

pub const default_nix_daemon_socket = "/nix/var/nix/daemon-socket/socket";

/// The name a `robots.txt` group is written for. It carries no version, and it
/// never may: a token that moved with a release stops matching such a group.
pub const product_token = "chock";

pub const user_agent = product_token ++ "/" ++ chock_version.text;

pub const Action = union(Kind) {
    git_commit: GitCommit,
    git_push: GitPush,
    git_branch_delete: GitBranchDelete,
    net_fetch: NetFetch,
    nix_build: NixBuild,
    file_write: FileWrite,
    workspace_apply: WorkspaceApply,
    model_select: ModelSelect,

    pub fn name(self: Action) []const u8 {
        return std.meta.activeTag(self).wireName();
    }

    pub fn summary(self: Action, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return switch (self) {
            .git_commit => |a| std.fmt.allocPrint(
                gpa,
                "commit {d} {s} in {s}, as \"{s}\"",
                .{ a.paths.len, plural(a.paths.len, "path", "paths"), a.repository, firstLine(a.message) },
            ),
            .git_push => |a| std.fmt.allocPrint(
                gpa,
                "set {s} on {s} ({s}) to {s}",
                .{ a.remote_ref, a.remote, a.remote_url, shortId(a.new_id) },
            ),
            .git_branch_delete => |a| std.fmt.allocPrint(
                gpa,
                "delete the branch {s}, at {s}, in {s}",
                .{ a.branch, shortId(a.points_at), a.repository },
            ),
            .net_fetch => |a| std.fmt.allocPrint(
                gpa,
                "read {s} {s} from the host {s}",
                .{ a.method.wireName(), a.url, a.host },
            ),
            .nix_build => |a| std.fmt.allocPrint(
                gpa,
                "realise {s} through the Nix daemon at {s}",
                .{ a.installable, a.daemon_socket },
            ),
            .file_write => |a| std.fmt.allocPrint(
                gpa,
                "put {d} bytes at {s}, outside the workspace",
                .{ a.contents.len, a.path },
            ),
            // A park must say in words that no branch moves. The answer to a
            // merge and to a park is the same "y".
            .workspace_apply => |a| switch (a.integration) {
                .move => |m| std.fmt.allocPrint(
                    gpa,
                    "land {d} {s} of the session in {s}, set {s} to {s}, and {s} it into {s}",
                    .{
                        a.objects.len,
                        plural(a.objects.len, "object", "objects"),
                        a.repository,
                        a.ref,
                        shortId(a.new_id),
                        m.landing.wireName(),
                        m.branch,
                    },
                ),
                .park => |p| if (p.wanted == null) std.fmt.allocPrint(
                    gpa,
                    "land {d} {s} of the session in {s}, and set {s} to {s}. " ++
                        "No branch of yours moves, because {s}",
                    .{
                        a.objects.len,
                        plural(a.objects.len, "object", "objects"),
                        a.repository,
                        a.ref,
                        shortId(a.new_id),
                        p.why.sentence(),
                    },
                ) else std.fmt.allocPrint(
                    gpa,
                    "land {d} {s} of the session in {s}, and set {s} to {s}. " ++
                        "No branch of yours moves: the {s} this apply would take does not " ++
                        "happen, because {s}",
                    .{
                        a.objects.len,
                        plural(a.objects.len, "object", "objects"),
                        a.repository,
                        a.ref,
                        shortId(a.new_id),
                        p.wanted.?.wireName(),
                        p.why.sentence(),
                    },
                ),
            },
            .model_select => |a| std.fmt.allocPrint(
                gpa,
                "use the model {s} from now on, in place of {s}",
                .{ a.to, a.from },
            ),
        };
    }

    pub fn detail(self: Action, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return switch (self) {
            .git_commit => |a| commit: {
                const paths = try indentedList(gpa, a.paths);
                defer gpa.free(paths);
                break :commit std.fmt.allocPrint(gpa,
                    \\repository: {s}
                    \\message: {s}
                    \\paths that become the commit:
                    \\{s}what those paths change:
                    \\{s}
                , .{ a.repository, a.message, paths, a.diff });
            },
            .git_push => |a| std.fmt.allocPrint(gpa,
                \\repository the objects come from: {s}
                \\remote: {s}
                \\remote address: {s}
                \\ref on the remote: {s}
                \\that ref is at: {s}
                \\that ref moves to: {s}
                \\what moves onto the remote:
                \\{s}
            , .{
                a.repository,
                a.remote,
                a.remote_url,
                a.remote_ref,
                if (a.old_id.len > 0) a.old_id else "nothing, the ref is not there yet",
                a.new_id,
                a.commits,
            }),
            .git_branch_delete => |a| std.fmt.allocPrint(gpa,
                \\repository: {s}
                \\branch: {s}
                \\that branch is at: {s}
                \\{s}
            , .{
                a.repository,
                a.branch,
                a.points_at,
                if (a.merged_into.len > 0)
                    "that commit is still reached by another ref, so nothing becomes unreachable"
                else
                    "no other ref reaches that commit, so this work stops being named",
            }),
            .net_fetch => |a| std.fmt.allocPrint(gpa,
                \\host: {s}
                \\address: {s}
                \\this reads and never writes: the method is {s}
                \\at most {d} bytes of the reply are kept
                \\no redirect is followed, because a redirect reaches a host this does not cover
            , .{ a.host, a.url, a.method.wireName(), a.max_bytes }),
            .nix_build => |a| std.fmt.allocPrint(gpa,
                \\installable: {s}
                \\daemon socket: {s}
                \\the store is written by the daemon, never by this process
            , .{ a.installable, a.daemon_socket }),
            .file_write => |a| std.fmt.allocPrint(gpa,
                \\path: {s}
                \\the workspace it sits outside of: {s}
                \\what is there now:
                \\{s}
                \\what will be there:
                \\{s}
            , .{
                a.path,
                a.workspace_root,
                a.previous orelse "nothing, the path is empty",
                a.contents,
            }),
            .workspace_apply => |a| apply: {
                const objects = try indentedList(gpa, a.objects);
                defer gpa.free(objects);
                const branch = try branchText(gpa, a);
                defer gpa.free(branch);
                const copies = try copiesText(gpa, a.copies);
                defer gpa.free(copies);
                break :apply std.fmt.allocPrint(gpa,
                    \\repository: {s}
                    \\the objects come from: {s}
                    \\the objects land in: {s}
                    \\ref: {s}
                    \\that ref is at: {s}
                    \\that ref moves to: {s}
                    \\{s}objects that land, {d} of them:
                    \\{s}{s}what the ref move changes:
                    \\{s}
                , .{
                    a.repository,
                    a.scratch_object_store,
                    a.project_object_store,
                    a.ref,
                    if (a.old_id.len > 0) a.old_id else "nothing, the ref is not there yet",
                    a.new_id,
                    branch,
                    a.objects.len,
                    objects,
                    copies,
                    a.diff,
                });
            },
            .model_select => |a| std.fmt.allocPrint(gpa,
                \\the model in use now: {s}
                \\the model in use after this: {s}
                \\every later turn of this session reaches the second one
            , .{ a.from, a.to }),
        };
    }
};

fn branchText(gpa: std.mem.Allocator, a: WorkspaceApply) std.mem.Allocator.Error![]u8 {
    return switch (a.integration) {
        .move => |m| std.fmt.allocPrint(gpa,
            \\
            \\your branch: {s}, and this apply moves it
            \\  how: {s}
            \\  that branch is at: {s}
            \\  that branch moves to: {s}
            \\  {s}
            \\  this was built and tested before you were asked, and it applies with no conflict
            \\
        , .{
            m.branch,
            m.landing.wireName(),
            m.at,
            m.to,
            m.landing.promise(),
        }),
        .park => |p| if (p.wanted == null) std.fmt.allocPrint(gpa,
            \\
            \\your branch: no branch of yours moves
            \\  why: {s}
            \\  read the work with `git log {s}`, and take it with `git merge {s}`
            \\
        , .{ p.why.sentence(), a.ref, a.ref }) else std.fmt.allocPrint(gpa,
            \\
            \\your branch: no branch of yours moves
            \\  this apply would take the {s}, and it does not happen, because {s}
            \\  the work still lands at {s}, and you take it with `git merge {s}`
            \\
        , .{ p.wanted.?.wireName(), p.why.sentence(), a.ref, a.ref }),
    };
}

/// Empty for a session with no copies, so the prompt gains nothing when the
/// `workspace` block carries no copying bind.
fn copiesText(gpa: std.mem.Allocator, copies: []const []const u8) std.mem.Allocator.Error![]u8 {
    if (copies.len == 0) return gpa.dupe(u8, "");
    const listed = try indentedList(gpa, copies);
    defer gpa.free(listed);
    return std.fmt.allocPrint(
        gpa,
        "files copied back over your own, {d} of them:\n{s}",
        .{ copies.len, listed },
    );
}

fn indentedList(gpa: std.mem.Allocator, items: []const []const u8) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (items) |item| {
        try out.appendSlice(gpa, "  ");
        try out.appendSlice(gpa, item);
        try out.append(gpa, '\n');
    }
    return out.toOwnedSlice(gpa);
}

fn firstLine(text: []const u8) []const u8 {
    return text[0 .. std.mem.indexOfScalar(u8, text, '\n') orelse text.len];
}

fn shortId(id: []const u8) []const u8 {
    return if (id.len > 7) id[0..7] else id;
}

fn plural(count: usize, one: []const u8, many: []const u8) []const u8 {
    return if (count == 1) one else many;
}

pub const Result = union(Kind) {
    git_commit: struct { commit_id: []u8 },
    git_push: struct { remote_ref: []u8, new_id: []u8 },
    git_branch_delete: struct { deleted_id: []u8 },
    /// The `Location` header, or empty. Reported and never followed.
    net_fetch: struct { status: u16, body: []u8, location: []u8 },
    nix_build: struct { out_paths: []u8 },
    file_write: struct { path: []u8, bytes_written: usize },
    workspace_apply: struct {
        objects_moved: usize,
        ref: []u8,
        new_id: []u8,
        /// The outcome and not the plan. A plan that said `merge` can end at
        /// `park`: the repository is read again before the branch moves.
        integration: integrate.Outcome,
    },
    model_select: struct { alias: []u8 },

    pub fn deinit(self: *Result, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .git_commit => |r| gpa.free(r.commit_id),
            .git_push => |r| {
                gpa.free(r.remote_ref);
                gpa.free(r.new_id);
            },
            .git_branch_delete => |r| gpa.free(r.deleted_id),
            .net_fetch => |r| {
                gpa.free(r.body);
                gpa.free(r.location);
            },
            .nix_build => |r| gpa.free(r.out_paths),
            .file_write => |r| gpa.free(r.path),
            .workspace_apply => |*r| {
                gpa.free(r.ref);
                gpa.free(r.new_id);
                r.integration.deinit(gpa);
            },
            .model_select => |r| gpa.free(r.alias),
        }
        self.* = undefined;
    }
};

/// Every address is wanted, not the first: `std.http.Client` resolves the name
/// again and dials whichever answer it likes.
pub const Resolver = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Address = network.Transport.Address;

    pub const max_addresses = 16;

    pub const LookupError = error{
        NotResolved,
        /// A refusal and not a truncation. The addresses past the bound would
        /// stay unchecked, and that is where a hostile zone puts the loopback.
        TooManyAddresses,
    };

    pub const VTable = struct {
        lookup: *const fn (
            ptr: *anyopaque,
            io: std.Io,
            host: []const u8,
            into: []Address,
        ) LookupError!usize,
    };

    pub fn lookup(self: Resolver, io: std.Io, host: []const u8, into: []Address) LookupError!usize {
        return self.vtable.lookup(self.ptr, io, host, into);
    }

    pub const system: Resolver = .{
        .ptr = @constCast(&system_marker),
        .vtable = &system_vtable,
    };
};

const system_marker: u8 = 0;

const system_vtable = Resolver.VTable{ .lookup = systemLookup };

fn systemLookup(
    ptr: *anyopaque,
    io: std.Io,
    host: []const u8,
    into: []Resolver.Address,
) Resolver.LookupError!usize {
    _ = ptr;
    if (into.len == 0) return error.TooManyAddresses;

    if (std.Io.net.IpAddress.parse(host, 0)) |parsed| {
        into[0] = parsed;
        return 1;
    } else |_| {}

    const name = std.Io.net.HostName.init(host) catch return error.NotResolved;
    var results: [Resolver.max_addresses]std.Io.net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results);

    var future = io.async(std.Io.net.HostName.lookup, .{ name, io, &queue, .{ .port = 0 } });
    defer future.cancel(io) catch {};

    var found: usize = 0;
    var too_many = false;
    while (queue.getOne(io)) |result| {
        switch (result) {
            .address => |address| {
                if (found == into.len) {
                    too_many = true;
                    continue;
                }
                into[found] = address;
                found += 1;
            },
            .canonical_name => {},
        }
    } else |_| {}

    if (too_many) return error.TooManyAddresses;
    if (found == 0) return error.NotResolved;
    return found;
}

pub const Context = struct {
    env: *const std.process.Environ.Map,
    roster: []const []const u8 = &.{},
    /// The default is the real resolver, so saying nothing keeps the guard.
    resolver: Resolver = .system,
    /// Only a test sets this, because its servers listen on the loopback
    /// interface. No project file can name a value here.
    reachable: *const fn (address: Resolver.Address) bool = network.addressIsReachable,
};

pub const Ask = struct {
    action: Action,
    reason: []const u8,
    agent_kind: []const u8,
    model_alias: []const u8,
    tool: []const u8,
    tool_call_id: []const u8,
    spawn_chain: []const event.SpawnLink = &.{},
    timeout_ms: i64 = Broker.default_timeout_ms,
    self_policy: []const chock_policy.ratchet.Restriction = &.{},
};

pub const Attempt = union(enum) {
    refused: Broker.Outcome,
    done: Done,

    pub const Done = struct {
        outcome: Broker.Outcome,
        result: Result,
    };
};

/// A refusal is not in here. A refusal is an `Attempt.refused`.
pub const PerformError = error{
    /// A ref that moved makes git exit nonzero, which is how the compare and
    /// swap refusals arrive.
    GitFailed,
    HostNotApproved,
    UrlNotUsable,
    AddressNotPermitted,
    FetchFailed,
    /// The bound applies to decoded bytes, so a compressed body that grows
    /// past it ends here as well.
    ResponseTooLarge,
    ResponseEncodingNotReadable,
    NixDaemonUnavailable,
    NixFailed,
    PathInsideWorkspace,
    PathNotAbsolute,
    WriteFailed,
    ObjectMissing,
    BadObjectId,
    ModelNotOnRoster,
} || git.Error;

pub const DescribeError = git.Error || error{
    GitFailed,
    PackedObjectsFound,
};

pub const Error = Broker.Error || PerformError;

/// The approval is written to the log whichever way it went, so an act that
/// failed while running is still recorded as approved.
pub fn run(
    broker: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    locked: anytype,
    ctx: Context,
    ask: Ask,
    diag: ?*?Diagnostic,
) Error!Attempt {
    const summary = try ask.action.summary(gpa);
    defer gpa.free(summary);
    const detail = try ask.action.detail(gpa);
    defer gpa.free(detail);

    const outcome = try broker.request(gpa, io, storage, locked, .{
        .action = ask.action.name(),
        .summary = summary,
        .detail = detail,
        .reason = ask.reason,
        .agent_kind = ask.agent_kind,
        .model_alias = ask.model_alias,
        .tool = ask.tool,
        .tool_call_id = ask.tool_call_id,
        .spawn_chain = ask.spawn_chain,
        .timeout_ms = ask.timeout_ms,
        .self_policy = ask.self_policy,
    }, diag);

    if (!outcome.permits()) return .{ .refused = outcome };
    return .{ .done = .{ .outcome = outcome, .result = try perform(gpa, io, ctx, ask.action, diag) } };
}

/// Nothing here checks whether the act was approved. `run` has done that.
pub fn perform(
    gpa: std.mem.Allocator,
    io: std.Io,
    ctx: Context,
    action: Action,
    diag: ?*?Diagnostic,
) PerformError!Result {
    return switch (action) {
        .git_commit => |a| performGitCommit(gpa, io, ctx, a, diag),
        .git_push => |a| performGitPush(gpa, io, ctx, a, diag),
        .git_branch_delete => |a| performGitBranchDelete(gpa, io, ctx, a, diag),
        .net_fetch => |a| performNetFetch(gpa, io, ctx, a, diag),
        .nix_build => |a| performNixBuild(gpa, io, ctx, a, diag),
        .file_write => |a| performFileWrite(gpa, io, a, diag),
        .workspace_apply => |a| performWorkspaceApply(gpa, io, ctx, a, diag),
        .model_select => |a| performModelSelect(gpa, ctx, a, diag),
    };
}

fn runGit(
    gpa: std.mem.Allocator,
    io: std.Io,
    ctx: Context,
    cwd: []const u8,
    argv: []const []const u8,
    diag: ?*?Diagnostic,
) PerformError![]u8 {
    var output = try git.run(gpa, io, ctx.env, cwd, argv, null);
    defer output.deinit(gpa);
    const exited_zero = switch (output.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!exited_zero) {
        // `output` is freed on the way out, so the diagnostic keeps a copy.
        if (diagnostic.wants(diag)) {
            _ = diagnostic.note(diag, .{ .git_refused_the_act = try gpa.dupe(u8, output.stderr) });
        }
        return error.GitFailed;
    }
    return gpa.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

fn performGitCommit(
    gpa: std.mem.Allocator,
    io: std.Io,
    ctx: Context,
    a: GitCommit,
    diag: ?*?Diagnostic,
) PerformError!Result {
    // `--` ends the options, so a path that starts with a dash is still a path.
    // `git add` first: `git commit` cannot name a path git has never tracked.
    var stage: std.ArrayList([]const u8) = .empty;
    defer stage.deinit(gpa);
    try stage.appendSlice(gpa, &.{ "add", "--" });
    try stage.appendSlice(gpa, a.paths);
    gpa.free(try runGit(gpa, io, ctx, a.repository, stage.items, diag));

    var commit: std.ArrayList([]const u8) = .empty;
    defer commit.deinit(gpa);
    try commit.appendSlice(gpa, &.{ "commit", "-m", a.message, "--" });
    try commit.appendSlice(gpa, a.paths);
    gpa.free(try runGit(gpa, io, ctx, a.repository, commit.items, diag));

    const commit_id = try runGit(gpa, io, ctx, a.repository, &.{ "rev-parse", "HEAD" }, diag);
    return .{ .git_commit = .{ .commit_id = commit_id } };
}

fn performGitPush(
    gpa: std.mem.Allocator,
    io: std.Io,
    ctx: Context,
    a: GitPush,
    diag: ?*?Diagnostic,
) PerformError!Result {
    const refspec = try std.fmt.allocPrint(gpa, "{s}:{s}", .{ a.new_id, a.remote_ref });
    defer gpa.free(refspec);

    if (a.old_id.len > 0) {
        const lease = try std.fmt.allocPrint(gpa, "--force-with-lease={s}:{s}", .{ a.remote_ref, a.old_id });
        defer gpa.free(lease);
        gpa.free(try runGit(gpa, io, ctx, a.repository, &.{ "push", lease, a.remote, refspec }, diag));
    } else {
        gpa.free(try runGit(gpa, io, ctx, a.repository, &.{ "push", a.remote, refspec }, diag));
    }

    return .{ .git_push = .{
        .remote_ref = try gpa.dupe(u8, a.remote_ref),
        .new_id = try gpa.dupe(u8, a.new_id),
    } };
}

fn performGitBranchDelete(
    gpa: std.mem.Allocator,
    io: std.Io,
    ctx: Context,
    a: GitBranchDelete,
    diag: ?*?Diagnostic,
) PerformError!Result {
    const branch_ref = try std.fmt.allocPrint(gpa, "refs/heads/{s}", .{a.branch});
    defer gpa.free(branch_ref);

    // git has no compare and swap for a branch delete, so this reads the
    // branch and compares it here.
    const at = try runGit(gpa, io, ctx, a.repository, &.{ "rev-parse", "--verify", branch_ref }, diag);
    defer gpa.free(at);
    if (!std.mem.eql(u8, at, a.points_at)) {
        if (diagnostic.wants(diag)) {
            var owned: Diagnostic = .{ .branch_moved = .{ .branch = "", .at = "", .approved = "" } };
            errdefer owned.deinit(gpa);
            const names = &owned.branch_moved;
            names.branch = try gpa.dupe(u8, a.branch);
            names.at = try gpa.dupe(u8, at);
            names.approved = try gpa.dupe(u8, a.points_at);
            _ = diagnostic.note(diag, owned);
        }
        return error.GitFailed;
    }

    gpa.free(try runGit(gpa, io, ctx, a.repository, &.{ "branch", "--delete", "--force", a.branch }, diag));
    return .{ .git_branch_delete = .{ .deleted_id = try gpa.dupe(u8, a.points_at) } };
}

fn performNetFetch(
    gpa: std.mem.Allocator,
    io: std.Io,
    ctx: Context,
    a: NetFetch,
    diag: ?*?Diagnostic,
) PerformError!Result {
    const uri = std.Uri.parse(a.url) catch return error.UrlNotUsable;
    if (!std.mem.eql(u8, uri.scheme, "http") and !std.mem.eql(u8, uri.scheme, "https")) {
        _ = diagnostic.note(diag, .{ .scheme_not_fetchable = uri.scheme });
        return error.UrlNotUsable;
    }

    const host_component = uri.host orelse return error.UrlNotUsable;
    // `toRawMaybeAlloc` allocates only when it must, so its result is never
    // freed on its own. It wants an arena.
    var host_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer host_arena_state.deinit();
    const host = try host_component.toRawMaybeAlloc(host_arena_state.allocator());
    if (!std.mem.eql(u8, host, a.host)) {
        if (diagnostic.wants(diag)) {
            _ = diagnostic.note(diag, .{ .host_not_approved = .{
                .approved = a.host,
                .named = try gpa.dupe(u8, host),
            } });
        }
        return error.HostNotApproved;
    }

    // Whoever runs the permitted zone decides what the name answers. A rule
    // about a host must not become a handle on 127.0.0.1 or 169.254.169.254.
    const port = uriPort(uri);
    var addresses: [Resolver.max_addresses]Resolver.Address = undefined;
    const found = ctx.resolver.lookup(io, host, &addresses) catch |err| {
        if (diagnostic.wants(diag)) {
            const about = Diagnostic.NetHost{ .host = try gpa.dupe(u8, host), .port = port };
            _ = diagnostic.note(diag, switch (err) {
                error.NotResolved => .{ .net_host_not_resolved = about },
                error.TooManyAddresses => .{ .net_address_not_permitted = about },
            });
        }
        return switch (err) {
            error.NotResolved => error.FetchFailed,
            error.TooManyAddresses => error.AddressNotPermitted,
        };
    };
    for (addresses[0..found]) |address| {
        if (ctx.reachable(address)) continue;
        if (diagnostic.wants(diag)) {
            _ = diagnostic.note(diag, .{ .net_address_not_permitted = .{
                .host = try gpa.dupe(u8, host),
                .port = port,
            } });
        }
        return error.AddressNotPermitted;
    }

    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();

    const protocol = std.http.Client.Protocol.fromUri(uri) orelse return error.UrlNotUsable;
    const pinned = try pinnedConnection(gpa, io, &client, host, addresses[0..found], port, protocol);

    var request = client.request(switch (a.method) {
        .get => .GET,
        .head => .HEAD,
    }, uri, .{
        .keep_alive = false,
        // `not_allowed` would turn a 302 into an error and lose the `Location`.
        .redirect_behavior = .unhandled,
        .connection = pinned,
        .headers = .{
            .user_agent = .{ .override = user_agent },
            // `std.http.Client` turns user information in a URL into an
            // `Authorization` header.
            .authorization = .omit,
        },
    }) catch {
        // `Client.deinit` asserts that no connection is still out, and there
        // is no `Request.deinit` here to give this one back.
        if (pinned) |connection| client.connection_pool.release(connection, io);
        return error.FetchFailed;
    };
    defer request.deinit();

    request.sendBodiless() catch return error.FetchFailed;

    var redirect_buffer: [4 * 1024]u8 = undefined;
    var response = request.receiveHead(&redirect_buffer) catch |err| switch (err) {
        error.HttpContentEncodingUnsupported => return error.ResponseEncodingNotReadable,
        else => return error.FetchFailed,
    };

    // `head.location` points into the read buffer the body writes over.
    const location = try gpa.dupe(u8, response.head.location orelse "");
    errdefer gpa.free(location);

    // `std.http.Client` advertises gzip and deflate on every request, and
    // `Response.reader` gives those bytes back compressed. Read this before
    // either reader is taken: both invalidate the head strings.
    const encoding = response.head.content_encoding;
    // A HEAD answer carries no body whatever its head says about encoding, and
    // `readerDecompressing` would wait for one.
    const has_body = a.method != .head;

    const decompress_buffer: []u8 = if (!has_body) &.{} else switch (encoding) {
        .identity => &.{},
        .gzip, .deflate => try gpa.alloc(u8, std.compress.flate.max_window_len),
        // Answered again so that a build which starts to offer one of these
        // finds a refusal and not the `unreachable` in `Decompress.init`.
        .zstd, .compress => return error.ResponseEncodingNotReadable,
    };
    defer gpa.free(decompress_buffer);

    var transfer_buffer: [4 * 1024]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const body_reader = if (has_body)
        response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer)
    else
        response.reader(&transfer_buffer);
    const body = body_reader.allocRemaining(gpa, .limited(a.max_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.ResponseTooLarge,
        error.ReadFailed => return error.FetchFailed,
    };

    return .{ .net_fetch = .{
        .status = @intFromEnum(response.head.status),
        .body = body,
        .location = location,
    } };
}

const max_ip4_text = "255.255.255.255".len;

const not_pinned: ?*std.http.Client.Connection = null;

/// A connection already open to a checked address. This closes the DNS
/// rebinding window: `std.http.Client` resolves the name a second time, and a
/// zone can answer differently.
///
/// Only IPv4 can be pinned. `HostName.validate` refuses a colon on Zig 0.16,
/// so an IPv6 address cannot go into the name `connectTcpOptions` takes. A
/// name that answers with IPv6 only is not pinned, and the rebinding window is
/// open for it. Refusing it would stop Chock reading anything on an IPv6 only
/// or NAT64 network.
fn pinnedConnection(
    gpa: std.mem.Allocator,
    io: std.Io,
    client: *std.http.Client,
    host: []const u8,
    checked: []const Resolver.Address,
    port: u16,
    protocol: std.http.Client.Protocol,
) PerformError!?*std.http.Client.Connection {
    if (std.Io.net.IpAddress.parse(host, port)) |_| return not_pinned else |_| {}

    const pin = firstIp4(checked) orelse return not_pinned;
    var text: [max_ip4_text]u8 = undefined;
    const written = std.fmt.bufPrint(&text, "{d}.{d}.{d}.{d}", .{
        pin.bytes[0], pin.bytes[1], pin.bytes[2], pin.bytes[3],
    }) catch return error.FetchFailed;

    if (protocol == .tls) {
        // `Connection.Tls.create` reads the bundle and asserts the time is
        // set, and the connection is made before `Client.request` here.
        var bundle: std.crypto.Certificate.Bundle = .empty;
        const now = std.Io.Clock.real.now(io);
        bundle.rescan(gpa, io, now) catch {
            bundle.deinit(gpa);
            return error.FetchFailed;
        };
        client.ca_bundle = bundle;
        client.now = now;
    }

    return client.connectTcpOptions(.{
        .host = std.Io.net.HostName.init(written) catch return error.FetchFailed,
        .port = port,
        .protocol = protocol,
        // The certificate is checked against this, and the pool is keyed on it.
        .proxied_host = std.Io.net.HostName.init(host) catch return error.FetchFailed,
        .proxied_port = port,
    }) catch return error.FetchFailed;
}

fn firstIp4(checked: []const Resolver.Address) ?std.Io.net.Ip4Address {
    for (checked) |address| switch (address) {
        .ip4 => |ip4| return ip4,
        .ip6 => |ip6| if (std.Io.net.Ip4Address.fromIp6(ip6)) |ip4| return ip4,
    };
    return null;
}

fn uriPort(uri: std.Uri) u16 {
    if (uri.port) |port| return port;
    return if (std.mem.eql(u8, uri.scheme, "https")) 443 else 80;
}

fn performNixBuild(
    gpa: std.mem.Allocator,
    io: std.Io,
    ctx: Context,
    a: NixBuild,
    diag: ?*?Diagnostic,
) PerformError!Result {
    std.Io.Dir.accessAbsolute(io, a.daemon_socket, .{}) catch |err| {
        _ = diagnostic.note(diag, .{ .nix_daemon_unreachable = .{ .path = a.daemon_socket, .err = err } });
        return error.NixDaemonUnavailable;
    };

    var child_env = try ctx.env.clone(gpa);
    defer child_env.deinit();
    // A plain `daemon` reads the ordinary socket, `unix://<path>` names one.
    if (std.mem.eql(u8, a.daemon_socket, default_nix_daemon_socket)) {
        try child_env.put("NIX_REMOTE", "daemon");
    } else {
        const remote = try std.fmt.allocPrint(gpa, "unix://{s}", .{a.daemon_socket});
        defer gpa.free(remote);
        try child_env.put("NIX_REMOTE", remote);
    }

    const out_paths = try runProgram(gpa, io, &child_env, &.{
        "nix",         "build",
        "--no-link",   "--print-out-paths",
        a.installable,
    }, diag) orelse return error.NixFailed;

    return .{ .nix_build = .{ .out_paths = out_paths } };
}

fn performFileWrite(
    gpa: std.mem.Allocator,
    io: std.Io,
    a: FileWrite,
    diag: ?*?Diagnostic,
) PerformError!Result {
    if (!std.fs.path.isAbsolute(a.path)) return error.PathNotAbsolute;
    // A write inside the workspace needs no approval, so one must not reach it.
    if (isInside(a.path, a.workspace_root)) return error.PathInsideWorkspace;

    var file = std.Io.Dir.createFileAbsolute(io, a.path, .{}) catch |err| {
        _ = diagnostic.note(diag, .{ .file_not_openable = .{ .path = a.path, .err = err } });
        return error.WriteFailed;
    };
    defer file.close(io);
    file.writeStreamingAll(io, a.contents) catch |err| {
        _ = diagnostic.note(diag, .{ .file_not_writable = .{ .path = a.path, .err = err } });
        return error.WriteFailed;
    };

    return .{ .file_write = .{
        .path = try gpa.dupe(u8, a.path),
        .bytes_written = a.contents.len,
    } };
}

fn performWorkspaceApply(
    gpa: std.mem.Allocator,
    io: std.Io,
    ctx: Context,
    a: WorkspaceApply,
    diag: ?*?Diagnostic,
) PerformError!Result {
    for (a.objects) |id| try checkObjectId(id);
    try checkObjectId(a.new_id);

    // Objects first: a ref that names a missing object is unreadable.
    var moved: usize = 0;
    for (a.objects) |id| {
        const source = try objectPath(gpa, a.scratch_object_store, id);
        defer gpa.free(source);
        const target = try objectPath(gpa, a.project_object_store, id);
        defer gpa.free(target);

        std.Io.Dir.copyFileAbsolute(source, target, io, .{ .make_path = true }) catch |err| switch (err) {
            error.FileNotFound => {
                // git writes no object it can read through the alternate, so
                // an earlier apply left this one in the project.
                std.Io.Dir.accessAbsolute(io, target, .{}) catch {
                    _ = diagnostic.note(diag, .{ .object_missing = id });
                    return error.ObjectMissing;
                };
            },
            else => {
                _ = diagnostic.note(diag, .{ .object_not_moved = .{ .path = id, .err = err } });
                return error.WriteFailed;
            },
        };
        moved += 1;
    }

    // git reads an empty old value as "this ref must not exist".
    gpa.free(try runGit(gpa, io, ctx, a.repository, &.{ "update-ref", a.ref, a.new_id, a.old_id }, diag));

    // The ref is set first, so a failure below leaves the work where a
    // `git merge` still reaches it.
    const integration = switch (a.integration) {
        .park => |p| integrate.Outcome{ .park = p },
        .move => |m| try integrate.moving(gpa, io, ctx.env, a.repository, m, diag),
    };

    return .{ .workspace_apply = .{
        .objects_moved = moved,
        .ref = try gpa.dupe(u8, a.ref),
        .new_id = try gpa.dupe(u8, a.new_id),
        .integration = integration,
    } };
}

fn performModelSelect(
    gpa: std.mem.Allocator,
    ctx: Context,
    a: ModelSelect,
    diag: ?*?Diagnostic,
) PerformError!Result {
    for (ctx.roster) |alias| {
        if (!std.mem.eql(u8, alias, a.to)) continue;
        return .{ .model_select = .{ .alias = try gpa.dupe(u8, a.to) } };
    }
    _ = diagnostic.note(diag, .{ .model_not_on_roster = a.to });
    return error.ModelNotOnRoster;
}

/// The separator check keeps `/home/a/projects` out of `/home/a/project`.
fn isInside(path: []const u8, root: []const u8) bool {
    const trimmed = std.mem.trimEnd(u8, root, std.fs.path.sep_str);
    if (trimmed.len == 0) return true;
    if (!std.mem.startsWith(u8, path, trimmed)) return false;
    if (path.len == trimmed.len) return true;
    return path[trimmed.len] == std.fs.path.sep;
}

fn objectPath(gpa: std.mem.Allocator, store: []const u8, id: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(gpa, "{s}{c}{s}{c}{s}", .{
        store,
        std.fs.path.sep,
        id[0..2],
        std.fs.path.sep,
        id[2..],
    });
}

/// An id becomes a path, so only a hexadecimal SHA-1 or SHA-256 name passes.
fn checkObjectId(id: []const u8) PerformError!void {
    if (id.len != 40 and id.len != 64) return error.BadObjectId;
    for (id) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!is_hex) return error.BadObjectId;
    }
}

/// Standard error is inherited and not piped: one pipe cannot deadlock.
fn runProgram(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    argv: []const []const u8,
    diag: ?*?Diagnostic,
) PerformError!?[]u8 {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .environ_map = env,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.NotFound,
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            _ = diagnostic.note(diag, .{ .command_not_started = .{ .path = argv[0], .err = err } });
            return error.Unexpected;
        },
    };

    var reader: std.Io.File.Reader = .initStreaming(child.stdout.?, io, &.{});
    const printed = reader.interface.allocRemaining(gpa, .unlimited) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            _ = child.wait(io) catch {};
            _ = diagnostic.note(diag, .{ .command_output_unreadable = argv[0] });
            return error.Unexpected;
        },
    };
    errdefer gpa.free(printed);

    const term = child.wait(io) catch |err| {
        _ = diagnostic.note(diag, .{ .command_wait_failed = .{ .path = argv[0], .err = err } });
        return error.Unexpected;
    };
    switch (term) {
        .exited => |code| if (code != 0) {
            gpa.free(printed);
            return null;
        },
        else => {
            gpa.free(printed);
            return null;
        },
    }
    return printed;
}

const testing = std.testing;

const LockedHandle = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

fn absoluteDirPath(io: std.Io, buffer: []u8, dir: std.Io.Dir) ![:0]u8 {
    const len = dir.realPath(io, buffer) catch return error.RealPathFailed;
    buffer[len] = 0;
    return buffer[0..len :0];
}

fn writeFileAbsolute(io: std.Io, path: []const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

fn gitOk(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    argv: []const []const u8,
) ![]u8 {
    var output = try git.run(gpa, testing.io, env, cwd, argv, null);
    defer output.deinit(gpa);
    // `zig build` reads a run step that wrote to standard error as a failure,
    // so the failure carries what git said and nothing is printed.
    if (output.term != .exited or output.term.exited != 0) {
        try testing.expectEqualStrings("", output.stderr);
    }
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    return gpa.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

const TestProject = struct {
    gpa: std.mem.Allocator,
    root_path: [:0]const u8,
    scratch_path: [:0]const u8,
    env: std.process.Environ.Map,

    fn init(gpa: std.mem.Allocator, tmp: std.testing.TmpDir) !TestProject {
        const io = testing.io;
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_path = try absoluteDirPath(io, &buffer, tmp.dir);

        var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const root_path = try std.fmt.bufPrintZ(&root_buffer, "{s}/project", .{tmp_path});
        try std.Io.Dir.createDirAbsolute(io, root_path, .default_dir);

        var scratch_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const scratch_path = try std.fmt.bufPrintZ(&scratch_buffer, "{s}/scratch", .{tmp_path});
        try std.Io.Dir.createDirAbsolute(io, scratch_path, .default_dir);

        var env = try std.testing.environ.createMap(gpa);
        errdefer env.deinit();
        // This tree sits inside Chock's own checkout, which git's upward
        // search reaches without a ceiling.
        try env.put("GIT_CEILING_DIRECTORIES", tmp_path);

        gpa.free(try gitOk(gpa, &env, root_path, &.{ "init", "-b", "main" }));
        gpa.free(try gitOk(gpa, &env, root_path, &.{ "config", "user.email", "test@example.com" }));
        gpa.free(try gitOk(gpa, &env, root_path, &.{ "config", "user.name", "Test" }));

        var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{root_path});
        try writeFileAbsolute(io, tracked_path, "hello\n");
        gpa.free(try gitOk(gpa, &env, root_path, &.{ "add", "tracked.txt" }));
        gpa.free(try gitOk(gpa, &env, root_path, &.{ "commit", "-m", "first commit" }));

        return .{
            .gpa = gpa,
            .root_path = try gpa.dupeZ(u8, root_path),
            .scratch_path = try gpa.dupeZ(u8, scratch_path),
            .env = env,
        };
    }

    fn deinit(self: *TestProject) void {
        self.gpa.free(self.root_path);
        self.gpa.free(self.scratch_path);
        self.env.deinit();
    }

    fn objectList(self: *const TestProject) ![]u8 {
        return gitOk(self.gpa, &self.env, self.root_path, &.{
            "cat-file", "--batch-all-objects", "--batch-check=%(objectname)",
        });
    }

    fn refList(self: *const TestProject) ![]u8 {
        return gitOk(self.gpa, &self.env, self.root_path, &.{ "show-ref", "--head" });
    }
};

const TestSession = struct {
    gpa: std.mem.Allocator,
    worktree: chock_workspace.worktree.Worktree,
    env: std.process.Environ.Map,

    fn init(gpa: std.mem.Allocator, project: *const TestProject) !TestSession {
        const io = testing.io;
        var wt = try chock_workspace.worktree.create(
            gpa,
            io,
            &project.env,
            project.root_path,
            project.scratch_path,
            "sess1",
            null,
        );
        errdefer wt.remove(gpa, io, &project.env, null) catch {};

        var env = try project.env.clone(gpa);
        errdefer env.deinit();
        try env.put("GIT_OBJECT_DIRECTORY", wt.object_store_source);
        const real_objects = try std.fs.path.join(gpa, &.{ wt.git_dir, "objects" });
        defer gpa.free(real_objects);
        try env.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", real_objects);

        return .{ .gpa = gpa, .worktree = wt, .env = env };
    }

    fn deinit(self: *TestSession, project: *const TestProject) void {
        self.env.deinit();
        self.worktree.remove(self.gpa, testing.io, &project.env, null) catch {};
    }

    fn commit(self: *const TestSession, rel_path: []const u8, contents: []const u8, message: []const u8) ![]u8 {
        const path = try std.fs.path.join(self.gpa, &.{ self.worktree.path, rel_path });
        defer self.gpa.free(path);
        try writeFileAbsolute(testing.io, path, contents);
        self.gpa.free(try gitOk(self.gpa, &self.env, self.worktree.path, &.{ "add", rel_path }));
        self.gpa.free(try gitOk(self.gpa, &self.env, self.worktree.path, &.{ "commit", "-m", message }));
        return gitOk(self.gpa, &self.env, self.worktree.path, &.{ "rev-parse", "HEAD" });
    }
};

const ask_every_action: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\        },
    \\    },
    \\}
;

const TestWaiter = struct {
    now_ms: i64 = 1_700_000_000_000,
    waits: usize = 0,
    gpa: std.mem.Allocator,
    store: chock_proto.storage.Storage,
    locked: *LockedHandle,
    decision: event.ApprovalDecision,
    failed: ?anyerror = null,

    fn waiter(self: *TestWaiter) Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = io;
        const self: *TestWaiter = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        const self: *TestWaiter = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        if (self.waits == 1) {
            self.answer(io) catch |err| {
                if (self.failed == null) self.failed = err;
            };
        }
        self.now_ms += @intCast(budget_ms);
        return .slept;
    }

    fn answer(self: *TestWaiter, io: std.Io) !void {
        var replay = try self.store.replay(self.gpa, io, 0);
        defer replay.deinit();
        var request_id: ?u64 = null;
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            if (parsed.value.event != .approval_request) continue;
            request_id = parsed.value.id;
        }
        const id = request_id orelse return error.NoRequestInTheLog;
        _ = try self.locked.append(self.gpa, io, .{ .approval_response = .{
            .request_id = id,
            .decision = self.decision,
            .responder = "ross",
        } }, self.now_ms);
    }
};

fn askAndAnswer(
    gpa: std.mem.Allocator,
    io: std.Io,
    decision: event.ApprovalDecision,
    ctx: Context,
    ask: Ask,
) !Attempt {
    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{
        .gpa = gpa,
        .store = store,
        .locked = &locked,
        .decision = decision,
    };

    const policy = try chock_policy.table.Table.parse(gpa, ask_every_action, null);
    defer chock_policy.table.Table.destroy(gpa, policy);

    const broker = Broker{ .policy = policy, .waiter = waiter.waiter() };
    const attempt = run(&broker, gpa, io, store, &locked, ctx, ask, null);
    if (waiter.failed) |err| return err;
    return attempt;
}

fn testAsk(action: Action) Ask {
    return .{
        .action = action,
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .model_alias = "main",
        .tool = "request_action",
        .tool_call_id = "call1",
    };
}

test "an approved workspace.apply moves the objects and updates the ref" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    var session = try TestSession.init(gpa, &project);
    defer session.deinit(&project);

    const new_id = try session.commit("agent.txt", "the agent wrote this\n", "work from the session");
    defer gpa.free(new_id);

    const objects_before = try project.objectList();
    defer gpa.free(objects_before);
    try testing.expect(std.mem.indexOf(u8, objects_before, new_id) == null);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ctx = Context{ .env = &project.env };
    const apply = try WorkspaceApply.describing(arena, io, ctx, .{
        .repository = project.root_path,
        .scratch_object_store = session.worktree.object_store_source,
        .ref = "refs/heads/main",
        .new_id = new_id,
        .wanted = .{ .none = .nobody_answered },
    }, null);

    try testing.expect(apply.objects.len >= 3);
    try testing.expect(apply.old_id.len > 0);
    try testing.expect(std.mem.indexOf(u8, apply.diff, "the agent wrote this") != null);

    var attempt = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .workspace_apply = apply }));
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expectEqual(Broker.Outcome.approved_by_user, attempt.done.outcome);
    try testing.expectEqual(apply.objects.len, attempt.done.result.workspace_apply.objects_moved);
    try testing.expectEqualStrings(new_id, attempt.done.result.workspace_apply.new_id);

    for (apply.objects) |id| {
        gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "cat-file", "-e", id }));
    }

    const head_now = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(head_now);
    try testing.expectEqualStrings(new_id, head_now);

    const shown = try gitOk(gpa, &project.env, project.root_path, &.{ "show", "refs/heads/main:agent.txt" });
    defer gpa.free(shown);
    try testing.expectEqualStrings("the agent wrote this", shown);
}

test "a refused workspace.apply leaves the user's repository byte for byte unchanged" {
    // Objects and refs both: a broker that moved the objects and refused the
    // ref leaves the refs identical and the object list longer.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    var session = try TestSession.init(gpa, &project);
    defer session.deinit(&project);

    const new_id = try session.commit("agent.txt", "the agent wrote this\n", "work from the session");
    defer gpa.free(new_id);

    const objects_before = try project.objectList();
    defer gpa.free(objects_before);
    const refs_before = try project.refList();
    defer gpa.free(refs_before);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ctx = Context{ .env = &project.env };
    const apply = try WorkspaceApply.describing(arena, io, ctx, .{
        .repository = project.root_path,
        .scratch_object_store = session.worktree.object_store_source,
        .ref = "refs/heads/main",
        .new_id = new_id,
        .wanted = .{ .none = .nobody_answered },
    }, null);
    try testing.expect(apply.objects.len >= 3);

    var attempt = try askAndAnswer(gpa, io, .refused_by_user, ctx, testAsk(.{ .workspace_apply = apply }));
    try testing.expect(attempt == .refused);
    try testing.expectEqual(Broker.Outcome.refused_by_user, attempt.refused);
    try testing.expect(!attempt.refused.permits());

    const objects_after = try project.objectList();
    defer gpa.free(objects_after);
    const refs_after = try project.refList();
    defer gpa.free(refs_after);

    try testing.expectEqualStrings(objects_before, objects_after);
    try testing.expectEqualStrings(refs_before, refs_after);

    for (apply.objects) |id| {
        gpa.free(try gitOk(gpa, &session.env, session.worktree.path, &.{ "cat-file", "-e", id }));
    }
}

test "a workspace.apply nobody can answer expires at once, and the repository is unchanged" {
    // `chock run` holds the exclusive lock on the session log while the
    // question is open, so nothing else can append an answer and the timeout
    // is zero.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    var session = try TestSession.init(gpa, &project);
    defer session.deinit(&project);

    const new_id = try session.commit("agent.txt", "nobody approved this\n", "work from the session");
    defer gpa.free(new_id);

    const objects_before = try project.objectList();
    defer gpa.free(objects_before);
    const refs_before = try project.refList();
    defer gpa.free(refs_before);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ctx = Context{ .env = &project.env };
    const apply = try WorkspaceApply.describing(arena, io, ctx, .{
        .repository = project.root_path,
        .scratch_object_store = session.worktree.object_store_source,
        .ref = "refs/chock/01SESSION",
        .new_id = new_id,
        .wanted = .{ .none = .nobody_answered },
    }, null);
    try testing.expect(apply.objects.len >= 3);
    try testing.expectEqualStrings("", apply.old_id);

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const policy = try chock_policy.table.Table.parse(gpa, ask_every_action, null);
    defer chock_policy.table.Table.destroy(gpa, policy);
    const broker = Broker{ .policy = policy, .waiter = Broker.SystemWaiter.waiter() };

    var ask = testAsk(.{ .workspace_apply = apply });
    ask.timeout_ms = 0;

    const attempt = try run(&broker, gpa, io, store, &locked, ctx, ask, null);
    try testing.expect(attempt == .refused);
    try testing.expectEqual(Broker.Outcome.expired, attempt.refused);

    const objects_after = try project.objectList();
    defer gpa.free(objects_after);
    const refs_after = try project.refList();
    defer gpa.free(refs_after);
    try testing.expectEqualStrings(objects_before, objects_after);
    try testing.expectEqualStrings(refs_before, refs_after);
}

test "a workspace.apply the project's own policy allows lands with nobody at the keyboard" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    var session = try TestSession.init(gpa, &project);
    defer session.deinit(&project);

    const new_id = try session.commit("agent.txt", "the agent wrote this\n", "work from the session");
    defer gpa.free(new_id);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ctx = Context{ .env = &project.env };
    const apply = try WorkspaceApply.describing(arena, io, ctx, .{
        .repository = project.root_path,
        .scratch_object_store = session.worktree.object_store_source,
        .ref = "refs/chock/01SESSION",
        .new_id = new_id,
        .wanted = .{ .none = .nobody_answered },
    }, null);

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const allow_apply: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "workspace.apply", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const policy = try chock_policy.table.Table.parse(gpa, allow_apply, null);
    defer chock_policy.table.Table.destroy(gpa, policy);
    const broker = Broker{ .policy = policy, .waiter = Broker.SystemWaiter.waiter() };

    var ask = testAsk(.{ .workspace_apply = apply });
    ask.timeout_ms = 0;

    var attempt = try run(&broker, gpa, io, store, &locked, ctx, ask, null);
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expectEqual(Broker.Outcome.allowed_by_policy, attempt.done.outcome);

    for (apply.objects) |id| {
        gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "cat-file", "-e", id }));
    }
    const ref_now = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/chock/01SESSION" });
    defer gpa.free(ref_now);
    try testing.expectEqualStrings(new_id, ref_now);

    const main_now = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(main_now);
    try testing.expect(!std.mem.eql(u8, main_now, new_id));
}

test "an action names its effect, and the effect is a diff and not a command" {
    const gpa = testing.allocator;

    try testing.expect(!@hasField(Ask, "summary"));
    try testing.expect(!@hasField(Ask, "detail"));

    const forbidden = [_][]const u8{ "command", "argv", "args", "cmd", "shell", "script" };
    inline for (@typeInfo(Action).@"union".fields) |field| {
        inline for (@typeInfo(field.type).@"struct".fields) |payload_field| {
            for (forbidden) |bad| {
                try testing.expect(!std.ascii.eqlIgnoreCase(payload_field.name, bad));
            }
        }
    }

    const diff =
        \\diff --git a/parser.zig b/parser.zig
        \\@@ -1 +1 @@
        \\-const limit = 4;
        \\+const limit = 8;
    ;
    const cases = [_]struct {
        action: Action,
        name: []const u8,
        effect: []const []const u8,
        never: []const u8,
    }{
        .{
            .action = .{ .git_commit = .{
                .repository = "/home/ross/project",
                .paths = &.{"parser.zig"},
                .message = "raise the limit",
                .diff = diff,
            } },
            .name = "git.commit",
            .effect = &.{ "/home/ross/project", "parser.zig", "raise the limit", "+const limit = 8;" },
            .never = "git commit",
        },
        .{
            .action = .{ .git_push = .{
                .repository = "/home/ross/project",
                .remote = "origin",
                .remote_url = "https://example.invalid/ross/project.git",
                .remote_ref = "refs/heads/main",
                .old_id = "1111111111111111111111111111111111111111",
                .new_id = "2222222222222222222222222222222222222222",
                .commits = "2222222 raise the limit",
            } },
            .name = "git.push",
            .effect = &.{
                "https://example.invalid/ross/project.git",
                "refs/heads/main",
                "1111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222",
                "2222222 raise the limit",
            },
            .never = "git push",
        },
        .{
            .action = .{ .git_branch_delete = .{
                .repository = "/home/ross/project",
                .branch = "spike",
                .points_at = "3333333333333333333333333333333333333333",
                .merged_into = "",
            } },
            .name = "git.branch.delete",
            .effect = &.{ "spike", "3333333333333333333333333333333333333333" },
            .never = "git branch",
        },
        .{
            .action = .{ .net_fetch = .{
                .host = "example.invalid",
                .url = "https://example.invalid/spec.txt",
            } },
            .name = "net.fetch",
            .effect = &.{ "example.invalid", "https://example.invalid/spec.txt", "GET" },
            .never = "curl",
        },
        .{
            .action = .{ .nix_build = .{ .installable = ".#chock" } },
            .name = "nix.build",
            .effect = &.{ ".#chock", default_nix_daemon_socket },
            .never = "nix build",
        },
        .{
            .action = .{ .file_write = .{
                .path = "/home/ross/.config/chock/roster.zon",
                .workspace_root = "/home/ross/project",
                .contents = ".{ .models = .{} }\n",
                .previous = ".{}\n",
            } },
            .name = "file.write",
            .effect = &.{ "/home/ross/.config/chock/roster.zon", ".{ .models = .{} }", ".{}" },
            .never = "tee",
        },
        .{
            .action = .{ .workspace_apply = .{
                .repository = "/home/ross/project",
                .scratch_object_store = "/tmp/sess1.objects",
                .project_object_store = "/home/ross/project/.git/objects",
                .ref = "refs/heads/main",
                .old_id = "1111111111111111111111111111111111111111",
                .new_id = "2222222222222222222222222222222222222222",
                .objects = &.{
                    "2222222222222222222222222222222222222222",
                    "4444444444444444444444444444444444444444",
                },
                .diff = diff,
                .integration = .{ .park = .{ .wanted = null, .why = .nobody_answered } },
            } },
            .name = "workspace.apply",
            .effect = &.{
                "refs/heads/main",
                "1111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222",
                "4444444444444444444444444444444444444444",
                "+const limit = 8;",
            },
            .never = "git update-ref",
        },
        .{
            .action = .{ .model_select = .{ .from = "main", .to = "review" } },
            .name = "model.select",
            .effect = &.{ "main", "review" },
            .never = "chock model",
        },
    };

    try testing.expectEqual(@as(usize, 8), @typeInfo(Action).@"union".fields.len);
    try testing.expectEqual(cases.len, @typeInfo(Action).@"union".fields.len);

    for (cases) |case| {
        try testing.expectEqualStrings(case.name, case.action.name());

        const summary = try case.action.summary(gpa);
        defer gpa.free(summary);
        const detail = try case.action.detail(gpa);
        defer gpa.free(detail);

        try testing.expect(summary.len > 0);
        try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, summary, '\n'));
        try testing.expect(std.mem.indexOf(u8, summary, case.never) == null);

        for (case.effect) |part| {
            if (std.mem.indexOf(u8, detail, part) == null) {
                try testing.expectEqualStrings(part, detail);
                return error.DetailDoesNotNameItsEffect;
            }
        }
        if (std.mem.indexOf(u8, detail, case.never) != null) {
            try testing.expectEqualStrings("a detail that names no command", detail);
            return error.DetailNamesACommand;
        }
    }
}

test "the copies a workspace block writes back are a line of the apply prompt" {
    const gpa = testing.allocator;

    const base = WorkspaceApply{
        .repository = "/home/ross/project",
        .scratch_object_store = "/tmp/sess1.objects",
        .project_object_store = "/home/ross/project/.git/objects",
        .ref = "refs/chock/01JQAAAAAAAAAAAAAAAAAAAAAA",
        .old_id = "",
        .new_id = "2222222222222222222222222222222222222222",
        .objects = &.{"2222222222222222222222222222222222222222"},
        .diff = "",
        .integration = .{ .park = .{ .wanted = null, .why = .nobody_answered } },
    };

    {
        const said = try (Action{ .workspace_apply = base }).detail(gpa);
        defer gpa.free(said);
        try testing.expect(std.mem.indexOf(u8, said, "copied back") == null);
    }

    {
        var apply = base;
        apply.copies = &.{ "scripts/release", "config.local.json" };
        const said = try (Action{ .workspace_apply = apply }).detail(gpa);
        defer gpa.free(said);
        try testing.expect(std.mem.indexOf(u8, said, "copied back over your own, 2 of them") != null);
        try testing.expect(std.mem.indexOf(u8, said, "  scripts/release\n") != null);
    }
}

test "the one line of an apply that parks says that no branch of yours moves" {
    const gpa = testing.allocator;

    const base = WorkspaceApply{
        .repository = "/home/ross/project",
        .scratch_object_store = "/tmp/sess1.objects",
        .project_object_store = "/home/ross/project/.git/objects",
        .ref = "refs/chock/01JQAAAAAAAAAAAAAAAAAAAAAA",
        .old_id = "",
        .new_id = "2222222222222222222222222222222222222222",
        .objects = &.{"2222222222222222222222222222222222222222"},
        .diff = "",
        .integration = .{ .park = .{ .wanted = null, .why = .nobody_answered } },
    };

    {
        var apply = base;
        apply.integration = .{ .park = .{ .wanted = null, .why = .policy_refused } };
        const said = try (Action{ .workspace_apply = apply }).summary(gpa);
        defer gpa.free(said);
        if (std.mem.indexOf(u8, said, "No branch of yours moves") == null) {
            try testing.expectEqualStrings("a summary that names the branch", said);
            return error.SummaryDoesNotSayTheBranchStays;
        }
        try testing.expect(std.mem.indexOf(u8, said, "workspace.integrate") != null);
        try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, said, '\n'));
    }

    {
        var apply = base;
        apply.integration = .{ .park = .{ .wanted = .merge, .why = .dirty_tree } };
        const said = try (Action{ .workspace_apply = apply }).summary(gpa);
        defer gpa.free(said);
        if (std.mem.indexOf(u8, said, "No branch of yours moves") == null) {
            try testing.expectEqualStrings("a summary that names the branch", said);
            return error.SummaryDoesNotSayTheBranchStays;
        }
        try testing.expect(std.mem.indexOf(u8, said, "merge") != null);
        try testing.expect(std.mem.indexOf(u8, said, "not committed") != null);
        try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, said, '\n'));
    }

    {
        var apply = base;
        apply.integration = .{ .move = .{
            .landing = .merge,
            .branch = "refs/heads/main",
            .at = "1111111111111111111111111111111111111111",
            .to = "3333333333333333333333333333333333333333",
        } };
        const said = try (Action{ .workspace_apply = apply }).summary(gpa);
        defer gpa.free(said);
        try testing.expect(std.mem.indexOf(u8, said, "No branch of yours moves") == null);
        try testing.expect(std.mem.indexOf(u8, said, "refs/heads/main") != null);
    }
}

test "an approved git.commit makes the commit the user read the diff of" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    const new_file = try std.fs.path.join(gpa, &.{ project.root_path, "added.txt" });
    defer gpa.free(new_file);
    try writeFileAbsolute(io, new_file, "brand new\n");

    const before = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "HEAD" });
    defer gpa.free(before);

    const ctx = Context{ .env = &project.env };
    var attempt = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .git_commit = .{
        .repository = project.root_path,
        .paths = &.{"added.txt"},
        .message = "add the new file",
        .diff = "+brand new\n",
    } }));
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);

    const after = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "HEAD" });
    defer gpa.free(after);
    try testing.expect(!std.mem.eql(u8, before, after));
    try testing.expectEqualStrings(after, attempt.done.result.git_commit.commit_id);

    const message = try gitOk(gpa, &project.env, project.root_path, &.{ "log", "-1", "--format=%s" });
    defer gpa.free(message);
    try testing.expectEqualStrings("add the new file", message);

    const content = try gitOk(gpa, &project.env, project.root_path, &.{ "show", "HEAD:added.txt" });
    defer gpa.free(content);
    try testing.expectEqualStrings("brand new", content);
}

test "git.commit stages only the paths the user read, and leaves the rest alone" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    const approved = try std.fs.path.join(gpa, &.{ project.root_path, "approved.txt" });
    defer gpa.free(approved);
    try writeFileAbsolute(io, approved, "the user read this\n");

    const sneaked = try std.fs.path.join(gpa, &.{ project.root_path, "sneaked.txt" });
    defer gpa.free(sneaked);
    try writeFileAbsolute(io, sneaked, "the user never read this\n");

    const ctx = Context{ .env = &project.env };
    var attempt = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .git_commit = .{
        .repository = project.root_path,
        .paths = &.{"approved.txt"},
        .message = "only the approved path",
        .diff = "+the user read this\n",
    } }));
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);

    const listed = try gitOk(gpa, &project.env, project.root_path, &.{ "show", "--name-only", "--format=", "HEAD" });
    defer gpa.free(listed);
    try testing.expectEqualStrings("approved.txt", listed);
}

test "an approved git.push moves the approved id onto the remote ref" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    var remote_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const remote_path = try std.fmt.bufPrintZ(&remote_buffer, "{s}/remote.git", .{project.scratch_path});
    try std.Io.Dir.createDirAbsolute(io, remote_path, .default_dir);
    gpa.free(try gitOk(gpa, &project.env, remote_path, &.{ "init", "--bare", "-b", "main" }));
    gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "remote", "add", "origin", remote_path }));
    gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "push", "origin", "refs/heads/main:refs/heads/main" }));

    const old_id = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "HEAD" });
    defer gpa.free(old_id);

    const changed = try std.fs.path.join(gpa, &.{ project.root_path, "tracked.txt" });
    defer gpa.free(changed);
    try writeFileAbsolute(io, changed, "hello again\n");
    gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "commit", "-am", "second commit" }));
    const new_id = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "HEAD" });
    defer gpa.free(new_id);

    const ctx = Context{ .env = &project.env };
    var attempt = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .git_push = .{
        .repository = project.root_path,
        .remote = "origin",
        .remote_url = remote_path,
        .remote_ref = "refs/heads/main",
        .old_id = old_id,
        .new_id = new_id,
        .commits = "second commit",
    } }));
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expectEqualStrings(new_id, attempt.done.result.git_push.new_id);

    const remote_head = try gitOk(gpa, &project.env, remote_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(remote_head);
    try testing.expectEqualStrings(new_id, remote_head);
}

test "git.push refuses when the remote is no longer where the user was told" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    var remote_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const remote_path = try std.fmt.bufPrintZ(&remote_buffer, "{s}/remote.git", .{project.scratch_path});
    try std.Io.Dir.createDirAbsolute(io, remote_path, .default_dir);
    gpa.free(try gitOk(gpa, &project.env, remote_path, &.{ "init", "--bare", "-b", "main" }));
    gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "remote", "add", "origin", remote_path }));
    gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "push", "origin", "refs/heads/main:refs/heads/main" }));

    const changed = try std.fs.path.join(gpa, &.{ project.root_path, "tracked.txt" });
    defer gpa.free(changed);
    try writeFileAbsolute(io, changed, "hello again\n");
    gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "commit", "-am", "second commit" }));
    const new_id = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "HEAD" });
    defer gpa.free(new_id);

    const remote_now = try gitOk(gpa, &project.env, remote_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(remote_now);

    const ctx = Context{ .env = &project.env };
    const stale = "0123456789012345678901234567890123456789";
    try testing.expect(!std.mem.eql(u8, stale, remote_now));

    try testing.expectError(error.GitFailed, askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .git_push = .{
        .repository = project.root_path,
        .remote = "origin",
        .remote_url = remote_path,
        .remote_ref = "refs/heads/main",
        .old_id = stale,
        .new_id = new_id,
        .commits = "second commit",
    } })));

    const remote_after = try gitOk(gpa, &project.env, remote_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(remote_after);
    try testing.expectEqualStrings(remote_now, remote_after);
}

test "an approved git.branch.delete removes the branch, and a moved branch is refused" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "branch", "spike" }));
    const points_at = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/spike" });
    defer gpa.free(points_at);

    const ctx = Context{ .env = &project.env };

    try testing.expectError(error.GitFailed, askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .git_branch_delete = .{
        .repository = project.root_path,
        .branch = "spike",
        .points_at = "0123456789012345678901234567890123456789",
        .merged_into = "refs/heads/main",
    } })));
    const still_there = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/spike" });
    defer gpa.free(still_there);
    try testing.expectEqualStrings(points_at, still_there);

    var attempt = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .git_branch_delete = .{
        .repository = project.root_path,
        .branch = "spike",
        .points_at = points_at,
        .merged_into = "refs/heads/main",
    } }));
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expectEqualStrings(points_at, attempt.done.result.git_branch_delete.deleted_id);

    var gone = try git.run(gpa, io, &project.env, project.root_path, &.{ "rev-parse", "--verify", "refs/heads/spike" }, null);
    defer gone.deinit(gpa);
    try testing.expect(gone.term != .exited or gone.term.exited != 0);
}

test "an approved file.write lands outside the workspace, and a path inside it is refused" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outside = try std.fs.path.join(arena, &.{ project.scratch_path, "outside.txt" });
    try writeFileAbsolute(io, outside, "the old bytes\n");

    const ctx = Context{ .env = &project.env };
    const write = try FileWrite.describing(arena, io, .{
        .path = outside,
        .workspace_root = project.root_path,
        .contents = "the new bytes\n",
    }, null);
    try testing.expectEqualStrings("the old bytes\n", write.previous.?);

    var attempt = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .file_write = write }));
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expectEqual(@as(usize, "the new bytes\n".len), attempt.done.result.file_write.bytes_written);

    const landed = try std.Io.Dir.cwd().readFileAlloc(io, outside, gpa, .limited(4096));
    defer gpa.free(landed);
    try testing.expectEqualStrings("the new bytes\n", landed);

    const inside = try std.fs.path.join(arena, &.{ project.root_path, "tracked.txt" });
    try testing.expectError(error.PathInsideWorkspace, askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .file_write = .{
        .path = inside,
        .workspace_root = project.root_path,
        .contents = "clobbered\n",
    } })));
    const untouched = try std.Io.Dir.cwd().readFileAlloc(io, inside, gpa, .limited(4096));
    defer gpa.free(untouched);
    try testing.expectEqualStrings("hello\n", untouched);
}

test "net.fetch refuses a URL whose host is not the one the approval covers" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    const ctx = Context{ .env = &project.env };
    try testing.expectError(error.HostNotApproved, askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .net_fetch = .{
        .host = "docs.example.invalid",
        .url = "https://evil.example.invalid/steal",
    } })));

    try testing.expectError(error.UrlNotUsable, askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .net_fetch = .{
        .host = "docs.example.invalid",
        .url = "file:///home/ross/.ssh/id_ed25519",
    } })));
}

test "nix.build refuses when nothing is listening on the daemon socket" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const missing = try std.fs.path.join(arena_state.allocator(), &.{ project.scratch_path, "no-daemon-here" });

    const ctx = Context{ .env = &project.env };
    try testing.expectError(error.NixDaemonUnavailable, askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .nix_build = .{
        .installable = ".#chock",
        .daemon_socket = missing,
    } })));
}

test "model.select refuses an alias the roster does not name" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    const ctx = Context{ .env = &project.env, .roster = &.{ "main", "review" } };

    var attempt = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .model_select = .{
        .from = "main",
        .to = "review",
    } }));
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expectEqualStrings("review", attempt.done.result.model_select.alias);

    try testing.expectError(error.ModelNotOnRoster, askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .model_select = .{
        .from = "main",
        .to = "a-model-the-user-never-offered",
    } })));
}

test "a refusal is not an error, and the act it refused never runs" {
    // An alias off the roster makes `perform` fail, so a `run` that performed
    // a refused act comes back as an error and not as a refusal.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    const ctx = Context{ .env = &project.env, .roster = &.{} };
    const ask = testAsk(.{ .model_select = .{ .from = "main", .to = "review" } });

    const attempt = try askAndAnswer(gpa, io, .refused_by_user, ctx, ask);
    try testing.expect(attempt == .refused);
    try testing.expectEqual(Broker.Outcome.refused_by_user, attempt.refused);

    const expired = try askAndAnswer(gpa, io, .expired, ctx, ask);
    try testing.expect(expired == .refused);
    try testing.expectEqual(Broker.Outcome.expired, expired.refused);

    // Without this the two refusals above could hold because `perform` won.
    try testing.expectError(
        error.ModelNotOnRoster,
        askAndAnswer(gpa, io, .approved_by_user, ctx, ask),
    );
}

// The effect and never a command, enforced by the build and not by a reviewer.
comptime {
    const forbidden = [_][]const u8{ "command", "argv", "args", "cmd", "shell", "script" };
    for (@typeInfo(Action).@"union".fields) |field| {
        const payload = @typeInfo(field.type);
        if (payload != .@"struct") {
            @compileError("an action payload must be a struct that names an effect: " ++ field.name);
        }
        if (payload.@"struct".fields.len == 0) {
            @compileError("an action payload with no field names no effect: " ++ field.name);
        }
        for (payload.@"struct".fields) |payload_field| {
            for (forbidden) |bad| {
                if (std.ascii.eqlIgnoreCase(payload_field.name, bad)) {
                    @compileError("an action names its effect, never a command: " ++
                        field.name ++ "." ++ payload_field.name);
                }
            }
        }
    }
    for (@typeInfo(Ask).@"struct".fields) |field| {
        if (std.mem.eql(u8, field.name, "summary") or std.mem.eql(u8, field.name, "detail")) {
            @compileError("Ask must not carry a summary or a detail: both come from the action itself");
        }
    }

    const decides = [_][]const u8{ "mode", "landing", "integration", "branch", "merge", "rebase", "squash" };
    for (@typeInfo(Ask).@"struct".fields) |field| {
        for (decides) |bad| {
            if (std.ascii.eqlIgnoreCase(field.name, bad)) {
                @compileError("an Ask carries an argument and never an answer, and \"" ++
                    field.name ++ "\" would decide how the work lands. The mode comes from " ++
                    "chock.zon, bounded by the workspace.integrate row");
            }
        }
    }
}

test "the model a refused selection named reaches the caller, and no longer only a terminal" {
    const gpa = testing.allocator;
    var env = try std.process.Environ.empty.createMap(gpa);
    defer env.deinit();
    const ctx = Context{ .env = &env, .roster = &.{"sonnet"} };

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.ModelNotOnRoster,
        perform(gpa, testing.io, ctx, .{ .model_select = .{ .from = "sonnet", .to = "opus" } }, &diag),
    );
    try testing.expectEqualStrings("opus", diag.?.model_not_on_roster);

    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "the roster of this session does not name the model opus",
        try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?}),
    );
}

test "a caller that wants no diagnostic gets the same refusal and stores nothing" {
    const gpa = testing.allocator;
    var env = try std.process.Environ.empty.createMap(gpa);
    defer env.deinit();
    const ctx = Context{ .env = &env, .roster = &.{"sonnet"} };
    try testing.expectError(
        error.ModelNotOnRoster,
        perform(gpa, testing.io, ctx, .{ .model_select = .{ .from = "sonnet", .to = "opus" } }, null),
    );
}

test "a write outside the workspace names the path it could not open" {
    const gpa = testing.allocator;
    var env = try std.process.Environ.empty.createMap(gpa);
    defer env.deinit();
    const ctx = Context{ .env = &env };

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    const missing = "/nonexistent-chock-directory/target.txt";
    try testing.expectError(error.WriteFailed, perform(gpa, testing.io, ctx, .{ .file_write = .{
        .path = missing,
        .workspace_root = "/some/other/place",
        .contents = "bytes",
        .previous = null,
    } }, &diag));
    try testing.expectEqualStrings(missing, diag.?.file_not_openable.path);

    var buffer: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.startsWith(u8, line, "the broker could not open "));
}

test "the user agent names the build, and opens with the token a robots.txt group is written for" {
    // A header with no version leaves a site operator unable to say which
    // Chock hit them, and a versioned token stops matching a `robots.txt`
    // group written for `chock`.
    try testing.expect(std.mem.startsWith(u8, user_agent, product_token ++ "/"));
    try testing.expectEqualStrings("chock", product_token);

    try testing.expect(chock_version.text.len != 0);
    try testing.expectEqualStrings(product_token ++ "/" ++ chock_version.text, user_agent);
}
