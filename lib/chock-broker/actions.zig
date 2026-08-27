//! The eight things the broker can do, and the one way to ask for one:
//! `git.commit`, `git.push`, `git.branch.delete`, `net.fetch` for one host,
//! `nix.build` with the daemon socket, `file.write` outside the workspace,
//! `workspace.apply`, and `model.select`.
//!
//! `lib/chock-broker/Broker.zig` asks, and it gives back one `Broker.Outcome`.
//! This file does the privileged work itself, and `run` below joins the two
//! into one call.
//!
//! ## An approval grants one act by the broker, never a capability
//!
//! Nothing here widens what the sandbox can do. `perform` runs on the host, in
//! the broker's own process, with the agent nowhere near it, and hands the
//! agent only a `Result`. The sandbox the agent runs in is not rebuilt, not
//! reconfigured, and not told that an approval happened at all.
//! `test/broker/actions.zig` proves that on a running system: it lets the
//! broker fetch a URL and apply a workspace, and then spawns a real sandbox and
//! watches it fail to reach the same URL and fail to write the same object
//! store.
//!
//! ## An action names its effect. It never names a command
//!
//! "Show the diff, not the command string. The user must approve the effect.
//! The user must not read a shell command and guess the effect."
//!
//! This is a property of the types here, not a rule a reviewer has to
//! remember:
//!
//! - Every `Action` payload holds nouns of the effect. A path, a ref, an
//!   object id, a host, a byte count, a diff. There is no variant for "run
//!   this", and the comptime block at the end of this file fails the build if
//!   a payload ever gains a field named `command`, `argv`, `args`, `cmd`,
//!   `shell`, or `script`.
//! - `Ask`, the only shape `run` takes, has no `summary` and no `detail`
//!   field, and the same comptime block fails the build if one appears. Both
//!   come from `Action.summary` and `Action.detail`, which read the effect
//!   fields. So a caller of this file cannot put a shell line in front of the
//!   user even by mistake: there is no field to put one in.
//! - The argument vectors `perform` hands to `git` and to `nix` are built
//!   inside `perform`, out of the same effect fields the user already read.
//!   They never come from the caller.
//!
//! ## The broker checks that the world is still where the user was told
//!
//! Three actions name where a thing is now as well as where it will be:
//! `git.push` names `old_id`, `git.branch.delete` names `points_at`, and
//! `workspace.apply` names `old_id`. Each one is passed to git as the old
//! value of a compare and swap, so the act the broker performs is exactly the
//! act the user approved. An agent that moves the ref between the question
//! and the answer does not get a different push; it gets a refusal.
//!
//! `workspace.apply` goes further: it moves exactly the object ids the
//! request listed, and no other. An object the agent wrote after the user
//! read the list stays in the scratch store.
//!
//! ## `net.fetch` checks the address, and not only the name
//!
//! An approval, or a policy row, says yes to a **name**. Whoever runs that
//! name's zone decides what it answers, so a name that answers `127.0.0.1` or
//! `169.254.169.254` would turn a rule about a host on the internet into a
//! handle on this machine and on the cloud metadata service, which hands out
//! credentials to whoever asks. `performNetFetch` therefore resolves the name
//! and checks every address it answers with, after the lookup and before
//! anything opens.
//!
//! **The check itself is `network.addressIsReachable` and is called, not
//! copied.** Two copies of a security check drift apart, and one of them then
//! guards a door nobody is walking through.
//!
//! **This is the right layer for it.** Every hop of
//! `lib/chock-broker/fetch.zig` comes back through this function, so a redirect
//! is checked in its own right, and a caller that is not that file is checked
//! too.
//!
//! **The address that was checked is the address that is dialled, for a name
//! with an IPv4 address.** A check before a name is resolved a second time
//! would guard nothing, because whoever runs the zone chooses the second
//! answer. So `pinnedConnection` opens the socket to a checked address and
//! hands `std.http.Client` a connection rather than a name, and the certificate
//! is still verified against the name.
//!
//! **A name that answers with IPv6 addresses only is not held to an address**,
//! because Zig 0.16 cannot write one into the `HostName` the dial takes. Such a
//! name is read by the ordinary path, and the rebinding window is open for it.
//! `pinnedConnection` holds the whole reason that is preferred to refusing it.
//! Every address is checked before anything opens either way.
//!
//! ## Why this file talks to git through `chock-workspace`
//!
//! `lib/chock-workspace/git.zig` says it is the only file in Chock that talks
//! to git, and it is right to. Five of the eight actions are git operations,
//! so this file imports that one and calls `git.run`, rather than keeping a
//! second spawn of `git` that could drift from it. `chock-workspace` does not
//! import `chock-broker`, so nothing here makes a cycle.

const std = @import("std");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const chock_version = @import("chock-version");
const chock_workspace = @import("chock-workspace");
const Broker = @import("Broker.zig");
const diagnostic = @import("diagnostic.zig");
const network = @import("network.zig");
/// Why the broker refused an act, or could not carry one out. One type for
/// the whole module: see `chock-broker/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;

const event = chock_proto.event;
const git = chock_workspace.git;

/// The eight action types. The enum is the tag of both `Action` and `Result`,
/// so a `Result` can never name a different action than the one that was
/// approved.
pub const Kind = enum {
    git_commit,
    git_push,
    git_branch_delete,
    net_fetch,
    nix_build,
    file_write,
    workspace_apply,
    model_select,

    /// The name the policy table matches and the log records. These are
    /// spelled with dots, and `chock-policy`'s own `git.*` prefix rule depends
    /// on that spelling.
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

/// The tool name a policy key carries when no tool call asked for the act.
///
/// `chock_policy.table.Key` has a `tool` field, and `Broker.request` asserts
/// that it is not empty, so every decision needs a name there. An agent asks
/// for an act with the `request_action` tool and that name goes in the field.
/// `chock run` also asks for `workspace.apply` after the agent loop has
/// ended, on the session's behalf, and there is no tool call behind that one.
/// It uses this name, which is the tool the agent would have called.
///
/// **A reader of the log needs the same value.** An `approval.response`
/// records the action and a tool call id, and never the tool, so a scan that
/// rebuilds the policy key finds the tool through the matching `tool.call`.
/// An act nothing called a tool for has no such call, and the scan reads this
/// constant instead. One copy, so the two cannot drift: see
/// `test/redteam/logscan.zig`.
pub const self_asked_tool = "request_action";

/// Make a commit in a repository on the host. The effect is the paths, the
/// message, and the diff those paths make.
pub const GitCommit = struct {
    /// Absolute host path of the repository the commit lands in.
    repository: []const u8,
    /// The paths that become the commit. The broker stages exactly these and
    /// nothing else, so a file the agent changed after the user read the diff
    /// is not carried in with it.
    paths: []const []const u8,
    /// The commit message.
    message: []const u8,
    /// The diff those paths make. This is what the user reads.
    diff: []const u8,
};

/// Move a ref on a remote to an object id. The effect is which id lands on
/// which ref of which remote, and which commits that carries.
pub const GitPush = struct {
    /// Absolute host path of the repository the objects come from.
    repository: []const u8,
    /// The remote's name, for example "origin".
    remote: []const u8,
    /// The remote's URL. The user needs to read where the work goes, not
    /// only the short name of the place.
    remote_url: []const u8,
    /// The ref on the remote that moves, for example "refs/heads/main".
    remote_ref: []const u8,
    /// Where `remote_ref` is now. Empty for a ref that does not exist yet.
    /// The broker passes this to git as a lease, so a remote that has moved
    /// since the user read this refuses the push.
    old_id: []const u8,
    /// The object id that lands on `remote_ref`. The broker pushes this id,
    /// not whatever a local branch points at when the answer arrives.
    new_id: []const u8,
    /// One line per commit that moves, oldest last, the way `git log
    /// --oneline` prints them.
    commits: []const u8,
};

/// Delete a branch in a repository on the host. The effect is which commit
/// stops being named, and whether anything else still reaches it.
pub const GitBranchDelete = struct {
    /// Absolute host path of the repository.
    repository: []const u8,
    /// The branch name, without `refs/heads/`.
    branch: []const u8,
    /// The object id the branch points at now. The broker checks the branch
    /// is still here before it deletes, so the act is the one approved.
    points_at: []const u8,
    /// The ref that already contains `points_at`, when one does. Empty when
    /// nothing else reaches the commit, which is the case where the work is
    /// lost and the user most needs to see it.
    merged_into: []const u8,
};

/// Read one URL on one host. The effect is which host is contacted and what
/// comes back.
pub const NetFetch = struct {
    /// The one host this approval covers. `perform` refuses a URL that names
    /// any other, and never follows a redirect, because a redirect is how one
    /// approved host becomes a second unapproved one. A redirect is
    /// **reported** rather than followed: see `Result.net_fetch`'s `location`,
    /// and `lib/chock-broker/fetch.zig`, which is what asks the policy about
    /// the next host before anything reaches it.
    host: []const u8,
    /// The whole URL. Its host must equal `host`.
    url: []const u8,
    /// The method. Only the two that read: an approval for `net.fetch` can
    /// never become a write to a remote service, because the type has no
    /// member that writes.
    method: Method = .get,
    /// The largest body `perform` keeps. A server Chock does not control
    /// decides how much it sends, so the broker decides how much it reads.
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

/// Build a Nix installable through the daemon. The effect is which
/// installable is realised, and through which daemon socket.
pub const NixBuild = struct {
    /// The flake reference, attribute path, or store path to realise.
    installable: []const u8,
    /// The daemon socket the build goes through. The sandbox never has this
    /// socket, and the broker does. `perform` refuses when nothing is at this
    /// path, rather than quietly building against the store on its own.
    daemon_socket: []const u8 = default_nix_daemon_socket,
};

/// Write one file outside the workspace. The effect is the path, the bytes
/// that are there now, and the bytes that will be there.
pub const FileWrite = struct {
    /// Absolute host path. `perform` refuses a relative one.
    path: []const u8,
    /// Absolute host path of the workspace this session runs in. `perform`
    /// refuses a `path` inside it: a write there needs no approval and must
    /// not be laundered through this action.
    workspace_root: []const u8,
    /// The bytes that will be at `path`.
    contents: []const u8,
    /// The bytes that are at `path` now, or null when nothing is there. The
    /// user reads the old against the new, which is the diff an approval asks
    /// for. `describing` reads this off the disk so a caller cannot leave it
    /// out.
    previous: ?[]const u8 = null,

    /// Build one of these by reading what is at `path` now, so the effect
    /// the user approves is the real before and after and not a guess. Every
    /// string comes out of `arena`, which the caller owns.
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
            // The user still learns that every byte there is replaced, and
            // learns that the broker did not show them all. A silent empty
            // "what is there now" would read as an empty file.
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

/// The most of an existing file `FileWrite.describing` reads back to show
/// the user. One mebibyte: a configuration file outside the workspace is
/// small, and a larger one is still replaced, only not shown in full.
pub const max_previous_bytes: usize = 1 << 20;

/// Land the session's work in the user's own repository. The agent's git
/// objects live in a scratch store the project never sees, and this is the one
/// act that carries them across. The effect is which objects move and which ref
/// moves.
pub const WorkspaceApply = struct {
    /// Absolute host path of the user's own project.
    repository: []const u8,
    /// Absolute host path of the session's own scratch object store, the
    /// directory `Worktree.object_store_source` names.
    scratch_object_store: []const u8,
    /// Absolute host path of the project's own object store, the directory
    /// the objects land in.
    project_object_store: []const u8,
    /// The ref that moves, for example "refs/heads/main".
    ref: []const u8,
    /// Where `ref` is now. Empty for a ref that does not exist yet. Passed to
    /// git as the old value of a compare and swap.
    old_id: []const u8,
    /// The object id `ref` moves to.
    new_id: []const u8,
    /// Every object id that moves, in the order they were found. `perform`
    /// moves exactly these.
    objects: []const []const u8,
    /// The diff from `old_id` to `new_id`. This is what the user reads.
    diff: []const u8,

    /// Build one of these by reading the two stores and the repository, so
    /// the object list, the old id, and the diff are what is really there.
    /// Every string comes out of `arena`, which the caller owns.
    pub fn describing(
        arena: std.mem.Allocator,
        io: std.Io,
        ctx: Context,
        params: struct {
            repository: []const u8,
            scratch_object_store: []const u8,
            ref: []const u8,
            new_id: []const u8,
        },
        diag: ?*?Diagnostic,
    ) DescribeError!WorkspaceApply {
        // Where the objects land. Read from git rather than assumed to be
        // `.git/objects`: a worktree, a bare repository, and a repository
        // with a separate git directory each put it somewhere else.
        const project_object_store = try describeGit(arena, io, ctx.env, params.repository, &.{
            "rev-parse", "--path-format=absolute", "--git-path", "objects",
        }, diag);

        // Where the ref is now. A ref that is not there yet is not a
        // failure: it is an empty old id, which git reads as "this ref must
        // not exist" when the broker moves it.
        const old_id = readRef(arena, io, ctx.env, params.repository, params.ref) catch |err| return err;

        const objects = try looseObjects(arena, io, params.scratch_object_store, diag);

        // The diff needs to read the new commit, which is still only in the
        // scratch store, so this one read names that store as an alternate.
        // A read of an alternate can never write to it: see
        // `lib/chock-workspace/worktree.zig`'s own doc comment on
        // `git_alternate_object_directories_env`.
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
        };
    }
};

/// Run one git call while a description is being built, and require it to
/// exit zero. The same shape as `runGit`, in the other error set: a
/// description is a read, and a read that fails is not an act that failed.
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
        // What git wrote is in a buffer this function frees on the way out,
        // so the diagnostic keeps a copy of it.
        if (diagnostic.wants(diag)) {
            _ = diagnostic.note(diag, .{ .git_refused_a_description = try arena.dupe(u8, output.stderr) });
        }
        return error.GitFailed;
    }
    return arena.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

/// The id `ref` is at, or an empty string when the repository has no such
/// ref. A missing ref is an ordinary answer here, not a failure.
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

/// Every loose object id in the store at `path`, sorted, so the list a user
/// reads is the same list twice running.
///
/// A pack file refuses the whole description: only `git gc` writes one, and
/// Chock never runs it inside a session, so a store that has one has been
/// rewritten by something else. Listing the loose half of such a store would
/// carry across less than the whole of the work, which is worse than saying
/// so.
///
/// Anything else that is not an object, for example the `tmp_obj_` file git
/// leaves while it writes one, is skipped and named, never dropped in
/// silence.
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
                // A notice and not a fault: the walk goes on and the call
                // succeeds. `entry.path` belongs to the walker, which moves
                // on at once, so the diagnostic keeps a copy.
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

/// The object id a store relative path names, for example `ab/cdef...`. The
/// caller owns the result.
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

/// Change which model the session talks to. The effect is which alias
/// replaces which.
pub const ModelSelect = struct {
    /// The alias in use now.
    from: []const u8,
    /// The alias to use next. `perform` refuses an alias the roster in
    /// `Context` does not name, so the agent cannot select a model the user
    /// never offered it.
    to: []const u8,
};

/// The largest body `net.fetch` keeps by default. Eight mebibytes, the same
/// bound `lib/chock-provider/Client.zig` puts on an error body, for the same
/// reason: the peer decides how much it sends.
pub const default_fetch_bytes: usize = 8 * 1024 * 1024;

/// Where the Nix daemon listens on an ordinary installation.
pub const default_nix_daemon_socket = "/nix/var/nix/daemon-socket/socket";

/// The name a `robots.txt` group is written for, and the name
/// `lib/chock-broker/fetch.zig` matches such a group against.
///
/// **It carries no version, and it never may.** A site that wrote a group for
/// `chock` has to keep matching every Chock, and a token that moved with each
/// release would silently stop honouring the file every time the number
/// changed. The convention matches on this token alone, which is why the header
/// below is allowed to say more than this.
pub const product_token = "chock";

/// What Chock calls itself when it reads a URL, `User-Agent` header and all.
///
/// **The version is here so a host that has to block one Chock can name it.**
/// A bare token tells an operator watching their logs which program is
/// misbehaving and not which build, and the answer to a misbehaving build is
/// usually to upgrade it.
///
/// **Built from `product_token`, so the two cannot drift.** A client that obeys
/// the rules written for a name it does not send is obeying nothing, and the
/// convention's own answer is that the token this opens with is what a group
/// names. The test at the end of this file pins that shape.
pub const user_agent = product_token ++ "/" ++ chock_version.text;

/// One privileged act, named by what it does to the machine.
///
/// Read this file's own top comment for why no payload here can carry a
/// command, and why that is checked by the build and not by a reviewer.
pub const Action = union(Kind) {
    git_commit: GitCommit,
    git_push: GitPush,
    git_branch_delete: GitBranchDelete,
    net_fetch: NetFetch,
    nix_build: NixBuild,
    file_write: FileWrite,
    workspace_apply: WorkspaceApply,
    model_select: ModelSelect,

    /// The name the policy table matches and the log records.
    pub fn name(self: Action) []const u8 {
        return std.meta.activeTag(self).wireName();
    }

    /// One line, for the list a client shows. It says what happens, in the
    /// words of the effect. The caller frees it.
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
            .workspace_apply => |a| std.fmt.allocPrint(
                gpa,
                "land {d} {s} of the session in {s}, and set {s} to {s}",
                .{
                    a.objects.len,
                    plural(a.objects.len, "object", "objects"),
                    a.repository,
                    a.ref,
                    shortId(a.new_id),
                },
            ),
            .model_select => |a| std.fmt.allocPrint(
                gpa,
                "use the model {s} from now on, in place of {s}",
                .{ a.to, a.from },
            ),
        };
    }

    /// The whole effect, for the user to approve: the diff, the object list
    /// and the ref move, or the host and the URL. It is never a line to run.
    /// The caller frees it.
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
                    // Two different facts for the user, and the second one is
                    // the one that loses work.
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
                break :apply std.fmt.allocPrint(gpa,
                    \\repository: {s}
                    \\the objects come from: {s}
                    \\the objects land in: {s}
                    \\ref: {s}
                    \\that ref is at: {s}
                    \\that ref moves to: {s}
                    \\objects that land, {d} of them:
                    \\{s}what the ref move changes:
                    \\{s}
                , .{
                    a.repository,
                    a.scratch_object_store,
                    a.project_object_store,
                    a.ref,
                    if (a.old_id.len > 0) a.old_id else "nothing, the ref is not there yet",
                    a.new_id,
                    a.objects.len,
                    objects,
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

/// One indented line per item, each ending in a newline. Empty for an empty
/// list. The caller frees the result.
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

/// The first line of `text`. A summary is one line, and a commit message is
/// not.
fn firstLine(text: []const u8) []const u8 {
    return text[0 .. std.mem.indexOfScalar(u8, text, '\n') orelse text.len];
}

/// The first seven characters of an object id, the length git itself
/// abbreviates to. The whole id is always in the detail; this is only for
/// the one line a client lists.
fn shortId(id: []const u8) []const u8 {
    return if (id.len > 7) id[0..7] else id;
}

fn plural(count: usize, one: []const u8, many: []const u8) []const u8 {
    return if (count == 1) one else many;
}

/// What the broker learned by doing the act. The tag is `Kind`, so a result
/// always names the same action the request did.
pub const Result = union(Kind) {
    git_commit: struct { commit_id: []u8 },
    git_push: struct { remote_ref: []u8, new_id: []u8 },
    git_branch_delete: struct { deleted_id: []u8 },
    /// `location` is the `Location` header, or empty when the response had
    /// none. **Reported and never followed**: the act stays one request to one
    /// host, and `lib/chock-broker/fetch.zig` is what decides whether the host
    /// this names may be reached at all.
    net_fetch: struct { status: u16, body: []u8, location: []u8 },
    nix_build: struct { out_paths: []u8 },
    file_write: struct { path: []u8, bytes_written: usize },
    workspace_apply: struct { objects_moved: usize, ref: []u8, new_id: []u8 },
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
            .workspace_apply => |r| {
                gpa.free(r.ref);
                gpa.free(r.new_id);
            },
            .model_select => |r| gpa.free(r.alias),
        }
        self.* = undefined;
    }
};

/// Where a host name becomes addresses, for `net.fetch` to check before it
/// opens anything.
///
/// **The one seam in this file**, and it exists for the reason
/// `lib/chock-broker/network.zig` gives for its own `Transport`: a check that
/// no test can drive is a check nobody knows the shape of. `system` is the
/// resolver of this machine and the default everywhere, so a caller that
/// builds a `Context` and says nothing gets the guard. There is no
/// configuration path to this field: it holds function pointers a Zig caller
/// sets, and a project file cannot name one.
///
/// **Every address is wanted, not the first.** `std.http.Client` resolves the
/// name again for itself and dials whichever answer it likes, so a check of one
/// answer out of several would leave the others unchecked.
pub const Resolver = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// The same type `lib/chock-broker/network.zig` checks, read from that
    /// file so the two cannot drift apart.
    pub const Address = network.Transport.Address;

    /// The most addresses one name may answer with. A name with more than
    /// this is refused rather than half checked: see
    /// `LookupError.TooManyAddresses`.
    pub const max_addresses = 16;

    pub const LookupError = error{
        /// The name did not resolve, whatever the reason was. **One member and
        /// not the resolver's own set**, because none of the reasons changes
        /// what happens next: there is no address, so there is nothing to
        /// check and nothing to read.
        NotResolved,
        /// The name answers with more than `max_addresses` addresses. **A
        /// refusal and not a truncation**, because a truncated answer would
        /// leave the addresses past the bound unchecked, and one of those is
        /// where a hostile zone would put the loopback interface.
        TooManyAddresses,
    };

    pub const VTable = struct {
        /// Every address `host` answers with, written into `into`. Gives back
        /// how many were written, which is never zero and never more than
        /// `into.len`.
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

    /// The resolver of this machine.
    pub const system: Resolver = .{
        .ptr = @constCast(&system_marker),
        .vtable = &system_vtable,
    };
};

/// What `Resolver.system` carries instead of state. It holds nothing and is
/// never read: the system lookup keeps no state between calls.
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

    // An address written out is not a name, and asking a resolver about one
    // would be a message to a nameserver about nothing. It answers itself, and
    // the address check then applies to it the same way it applies to a name's
    // answer.
    //
    // The port is zero throughout. Nothing here connects, and the address check
    // reads only the address bytes.
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

/// Everything `perform` needs that is not part of the effect itself.
pub const Context = struct {
    /// The environment every `git` and `nix` call starts from. See
    /// `lib/chock-workspace/git.zig`'s own top comment for why this is a
    /// parameter and not something the library reads for itself.
    env: *const std.process.Environ.Map,
    /// The model aliases `model.select` may choose between. Empty refuses
    /// every selection, which is the safe reading of a session that has no
    /// roster.
    roster: []const []const u8 = &.{},
    /// Where `net.fetch` turns a host name into the addresses it checks.
    /// **The default is the real resolver**, so a caller cannot leave the
    /// guard off by saying nothing.
    resolver: Resolver = .system,
    /// Whether a connection may be opened to an address at all. **The default
    /// is the production check**, so a caller that says nothing gets the
    /// guard, and there is no configuration path to this field: it holds a
    /// function pointer a Zig caller sets, and a project file cannot name one.
    ///
    /// **One caller sets it, and it is a test.** Every server in
    /// `test/broker/fetch.zig` listens on the loopback interface, which is
    /// what `network.addressIsReachable` refuses. A test that has to prove
    /// **where** a connection really went needs the address it checks and the
    /// address it dials to be one and the same, so it says here that the
    /// loopback interface counts. The tests about the guard itself leave this
    /// field alone.
    reachable: *const fn (address: Resolver.Address) bool = network.addressIsReachable,
};

/// One request for one act. There is no `summary` field and no `detail`
/// field on purpose: see this file's own top comment.
pub const Ask = struct {
    action: Action,
    /// The reason the agent gave.
    reason: []const u8,
    agent_kind: []const u8,
    model_alias: []const u8,
    tool: []const u8,
    tool_call_id: []const u8,
    spawn_chain: []const event.SpawnLink = &.{},
    timeout_ms: i64 = Broker.default_timeout_ms,
    /// What the asking session promised about itself, folded from its own
    /// `policy.self` events. Carried straight to `Broker.Request.self_policy`,
    /// which is where it is applied and where its own doc comment says why
    /// this is the broker's job and not the agent's.
    self_policy: []const chock_policy.ratchet.Restriction = &.{},
};

/// What one `run` call ended as.
pub const Attempt = union(enum) {
    /// The decision did not permit the act, so nothing ran. The outcome says
    /// which of the four ways it was refused.
    refused: Broker.Outcome,
    /// The decision permitted the act and the broker did it.
    done: Done,

    pub const Done = struct {
        outcome: Broker.Outcome,
        result: Result,
    };
};

/// What doing the act can fail with. A refusal is not in here: a refusal is
/// an `Attempt.refused`.
pub const PerformError = error{
    /// A `git` call exited nonzero. This covers the compare and swap
    /// refusals too: a ref that moved since the user read the request makes
    /// git exit nonzero, on purpose.
    GitFailed,
    /// The URL names a host other than the one the approval covers.
    HostNotApproved,
    /// The URL is not one this broker can fetch: a bad URL, or a scheme
    /// other than http and https.
    UrlNotUsable,
    /// The host resolved onto this machine rather than onto the network. See
    /// `performNetFetch`, and `network.addressIsReachable`, which is the one
    /// place that decides.
    AddressNotPermitted,
    /// The fetch itself failed: no connection, or a broken response.
    FetchFailed,
    /// The response body passed `NetFetch.max_bytes`. The bound is measured on
    /// the bytes a reader gets, so a compressed body that grows past it while
    /// it is decoded ends here as well.
    ResponseTooLarge,
    /// The site answered in a content encoding this build cannot decode.
    /// `performNetFetch` asks for gzip and deflate, so this is a site that
    /// answered in something it was not offered. **The answer is a refusal and
    /// never the undecoded bytes**: a body nothing can read must not reach a
    /// model dressed as the page.
    ResponseEncodingNotReadable,
    /// Nothing is listening at `NixBuild.daemon_socket`.
    NixDaemonUnavailable,
    /// `nix build` exited nonzero.
    NixFailed,
    /// `FileWrite.path` is inside `FileWrite.workspace_root`.
    PathInsideWorkspace,
    /// `FileWrite.path` is not absolute.
    PathNotAbsolute,
    /// The file could not be written.
    WriteFailed,
    /// An object id the request listed is in neither store.
    ObjectMissing,
    /// An object id is not the hexadecimal name of a git object.
    BadObjectId,
    /// `ModelSelect.to` is not on the roster.
    ModelNotOnRoster,
} || git.Error;

/// What building a description of an act can fail with. A description reads
/// the machine, so it can fail the same ways a read fails.
pub const DescribeError = git.Error || error{
    /// A `git` call exited nonzero while the description was being read.
    GitFailed,
    /// The scratch object store holds a pack file. Only `git gc` makes one,
    /// and Chock never runs it inside a session, so this is a store that
    /// something else has already rewritten. An apply that listed only the
    /// loose objects would carry across less than the whole of the work, so
    /// it refuses instead.
    PackedObjectsFound,
};

/// What `run` can fail with: everything the log can fail with, and
/// everything doing the act can fail with.
pub const Error = Broker.Error || PerformError;

/// Ask for one act, and do it when the answer permits it. This is the whole
/// approval flow in one call, and it is the only entry point a caller needs.
///
/// `storage` and `locked` are what `Broker.request` needs; see its own doc
/// comment. The approval is written to the log whichever way it went, so an
/// act that was approved and then failed while running is still recorded as
/// approved.
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

/// Do one act, outside the sandbox. `run` calls this after the answer
/// permits it. Nothing here asks whether it was approved: the caller already
/// knows, and a second check in a second place is a second thing that can
/// disagree with the first.
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

/// Run one git call and require it to exit zero. The trimmed standard output
/// comes back, owned by the caller.
///
/// A nonzero exit is a runtime fault, never an assertion: the compare and
/// swap refusals of `git.push` and `workspace.apply` arrive here, and so
/// does an ordinary rejected push. Recovery is not silent, so what git said
/// on standard error travels in `diag`, when the caller asked for one.
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
        // What git wrote is in a buffer this function frees on the way out,
        // so the diagnostic keeps a copy of it.
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
    // Exactly the paths the user read the diff of. `--` ends the options, so
    // a path that starts with a dash is still a path. `git add` first,
    // because a path git has never tracked cannot be named to `git commit`
    // at all, and then `git commit -- <paths>` commits those paths alone,
    // whatever else the index happens to hold.
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
    // The id the user approved, by name, never a local branch that could
    // have moved since the question was asked.
    const refspec = try std.fmt.allocPrint(gpa, "{s}:{s}", .{ a.new_id, a.remote_ref });
    defer gpa.free(refspec);

    if (a.old_id.len > 0) {
        // The lease. A remote that is no longer where the user was told it
        // was makes git refuse, which is the answer this design wants: the
        // act on offer is no longer the act that was approved.
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

    // git has no compare and swap for a branch delete the way it has one for
    // a push, so the broker reads where the branch is and compares it
    // itself. A branch that moved since the question is not the branch the
    // user answered about.
    const at = try runGit(gpa, io, ctx, a.repository, &.{ "rev-parse", "--verify", branch_ref }, diag);
    defer gpa.free(at);
    if (!std.mem.eql(u8, at, a.points_at)) {
        // `at` is freed by the defer above, so every name is copied together.
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
    // `toRawMaybeAlloc` gives back a slice of the URL itself when there is
    // nothing to decode, and allocates only when there is, so its result is
    // never freed on its own. An arena that ends with this check is the way
    // its own doc comment asks for it to be called.
    var host_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer host_arena_state.deinit();
    const host = try host_component.toRawMaybeAlloc(host_arena_state.allocator());
    // "net.fetch for one host". The host is what the user read.
    if (!std.mem.eql(u8, host, a.host)) {
        // `host` lives in an arena this function ends, so it is copied.
        if (diagnostic.wants(diag)) {
            _ = diagnostic.note(diag, .{ .host_not_approved = .{
                .approved = a.host,
                .named = try gpa.dupe(u8, host),
            } });
        }
        return error.HostNotApproved;
    }

    // **The address the name answers with is checked as well as the name.**
    // Whoever runs the permitted zone decides what the name resolves to, so a
    // rule about a host on the internet would otherwise become a handle on this
    // machine and on the cloud metadata service beside it, which hands out
    // credentials to whoever asks. `network.addressIsReachable` is the one
    // place that decides, and it is called and not copied: two copies of a
    // security check drift apart.
    //
    // **This is where the check belongs, and not a layer above.** Every hop of
    // `lib/chock-broker/fetch.zig` comes back through this function, so a
    // redirect is checked in its own right without that file holding a second
    // copy, and a caller of this file that is not that one is checked too.
    //
    // **The checked address is also the address that is dialled.** See
    // `pinnedConnection`: `std.http.Client` would otherwise resolve the name a
    // second time for itself, and a zone that answered differently between the
    // two lookups would reach an address nobody checked.
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
            // A name that does not resolve is an ordinary fault and not a
            // refusal: nothing was reached because nothing could be.
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
        // A redirect is how one approved host becomes a second unapproved
        // one. The same reasoning `lib/chock-provider/Client.zig` gives.
        //
        // **`unhandled` and not `not_allowed`, and the act is no wider for
        // it.** Both leave the redirect unfollowed. `not_allowed` turns a 302
        // into an error, which loses the one fact a caller needs to ask the
        // policy about the next host; `unhandled` hands the response back and
        // lets this function report the `Location`. Nothing in this file ever
        // opens a second connection.
        .redirect_behavior = .unhandled,
        // Already open, and open to an address this function checked. Null for
        // a host that is written out as an address, and null for a name that
        // answers with IPv6 addresses only, which both leave the ordinary path:
        // see `pinnedConnection`.
        .connection = pinned,
        .headers = .{
            // Chock says who it is and which build it is, because a site
            // operator is entitled to know, and because an operator who has to
            // block one Chock can then name the build rather than the program.
            // `lib/chock-broker/fetch.zig` matches `robots.txt` groups against
            // the token this opens with: see `product_token`.
            .user_agent = .{ .override = user_agent },
            // **The one place a credential could leave.** `std.http.Client`
            // turns user information in a URL into an `Authorization` header,
            // and every credential lives in the store. A URL that carries one
            // is refused a layer above as well: see
            // `lib/chock-broker/fetch.zig`. Two answers, because this action
            // has callers that are not that file.
            .authorization = .omit,
        },
    }) catch {
        // `Request.deinit` is what gives a connection back to the client, and
        // there is no request to do it here. `Client.deinit` asserts that
        // nothing is still out, so an unused connection has to go back now.
        if (pinned) |connection| client.connection_pool.release(connection, io);
        return error.FetchFailed;
    };
    defer request.deinit();

    request.sendBodiless() catch return error.FetchFailed;

    var redirect_buffer: [4 * 1024]u8 = undefined;
    var response = request.receiveHead(&redirect_buffer) catch |err| switch (err) {
        // A site that answered in an encoding this build did not offer. Std
        // refuses the head before a byte of the body is read, so nothing here
        // could hand the caller a page even if it wanted to.
        error.HttpContentEncodingUnsupported => return error.ResponseEncodingNotReadable,
        else => return error.FetchFailed,
    };

    // Copied before the body is read. `head.location` points into the
    // connection's own read buffer, which reading the body writes over.
    const location = try gpa.dupe(u8, response.head.location orelse "");
    errdefer gpa.free(location);

    // **Chock asks every site for gzip and deflate, so it has to read them.**
    // `std.http.Client` advertises them on every request through
    // `Request.default_accept_encoding`, and essentially every real site takes
    // the offer. `Response.reader` gives those bytes back exactly as they
    // arrived, which is how a fetched page reached the model as unreadable
    // bytes and not as a page. `readerDecompressing` is std's own answer, and
    // std's own `Client.fetch` uses it.
    //
    // **`lib/chock-provider/Client.zig` met the same fault and asked for
    // `identity` instead, and the two answers are both right.** That one
    // streams, so a decompressor's own framing would decide when a token
    // becomes visible. This one reads a whole page and hands it over at the
    // end, so nothing is waiting on it and the compressed page is the smaller
    // request.
    //
    // Read before either reader is taken, because both invalidate the strings
    // of the head.
    const encoding = response.head.content_encoding;
    // **A HEAD answer carries no body whatever its head says about encoding**,
    // and only `Response.reader` knows that. `readerDecompressing` would wait
    // for a body that is never sent.
    const has_body = a.method != .head;

    const decompress_buffer: []u8 = if (!has_body) &.{} else switch (encoding) {
        .identity => &.{},
        .gzip, .deflate => try gpa.alloc(u8, std.compress.flate.max_window_len),
        // Neither is offered, so `receiveHead` has already turned this away
        // above. It is answered again rather than left to the `unreachable`
        // inside `std.http.Decompress.init`, because a build that starts
        // offering one of them must find a refusal here and not a panic.
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

/// The most bytes an IPv4 address takes when it is written out.
const max_ip4_text = "255.255.255.255".len;

/// What `pinnedConnection` gives back when the connection is held to nothing.
/// `std.http.Client` then resolves the name for itself and dials what that
/// second answer gives, which is the ordinary path of every other HTTP client.
const not_pinned: ?*std.http.Client.Connection = null;

/// The connection one hop will use, already open to an address
/// `performNetFetch` has checked. Null when the ordinary path of
/// `std.http.Client` reaches the same address anyway.
///
/// **This is what closes the window between the two lookups.**
/// `performNetFetch` resolves the name and checks every address it answers
/// with. `std.http.Client` then resolves that same name again for itself, and
/// a zone that answered differently the second time would reach an address
/// nobody checked. That is DNS rebinding, and `169.254.169.254` is what it
/// reaches for: the cloud metadata service hands out credentials to whoever
/// asks. So the socket is opened here, to an address that was checked, and the
/// client is handed a connection rather than a name.
///
/// **The certificate is still checked against the name.**
/// `ConnectTcpOptions` carries two hosts: `host` is where the socket goes, and
/// `proxied_host` is what `std.crypto.tls.Client` verifies the certificate
/// against and what the connection pool is keyed on. Measured against real
/// hosts on Zig 0.16: a connection dialled at one site's address and verified
/// against its own name gets a 200, the same connection verified against a
/// different site's name fails to handshake, and one verified against the
/// address rather than the name fails as well. Nothing here turns
/// verification off, and a fix that did would be worse than the hole it
/// closes.
///
/// **Only IPv4 can be pinned. A name that answers with IPv6 addresses only is
/// NOT pinned, and the rebinding window is open for it.** That is a deliberate
/// decision and not an oversight, so read the whole of this before changing it.
///
/// The mechanism is the limit. `connectTcpOptions` takes a
/// `std.Io.net.HostName` for the address it dials, and `HostName.validate`
/// refuses a colon, so an IPv6 address cannot be written into one on Zig 0.16.
/// Such a name therefore falls back to the ordinary path, where
/// `std.http.Client` resolves the name a second time and dials what that second
/// answer gives. A zone that answers differently between the two lookups then
/// reaches an address nobody checked.
///
/// **The attacker picks when this applies**, because whoever runs the zone
/// decides which records it answers, and one AAAA record with no A record
/// beside it is enough to take the fallback.
///
/// **The decision is to keep IPv6-only networks working.** Refusing such a name
/// leaves Chock unable to read anything at all on an IPv6-only or a NAT64
/// network, which is the larger cost of the two.
///
/// **Every address is still checked before anything is dialled, IPv6
/// included.** `performNetFetch` does that above, over every address the
/// lookup gave. Losing that check would be much worse than losing the pin: the
/// pin holds a checked answer, and the check is what makes an answer checked at
/// all.
fn pinnedConnection(
    gpa: std.mem.Allocator,
    io: std.Io,
    client: *std.http.Client,
    host: []const u8,
    checked: []const Resolver.Address,
    port: u16,
    protocol: std.http.Client.Protocol,
) PerformError!?*std.http.Client.Connection {
    // A host written out as an address has no zone and no name server behind
    // it. Both lookups are the same pure parse of the same bytes, so there is
    // no second answer for anybody to change and nothing to hold the
    // connection to.
    if (std.Io.net.IpAddress.parse(host, port)) |_| return not_pinned else |_| {}

    // **The IPv6-only fallback, and it is deliberate.** No IPv4 address means
    // no address this can write into a `HostName`, so the connection is not
    // held and the rebinding window is open for this name. See this function's
    // own doc comment, which says why that is preferred to refusing the name.
    const pin = firstIp4(checked) orelse return not_pinned;
    var text: [max_ip4_text]u8 = undefined;
    const written = std.fmt.bufPrint(&text, "{d}.{d}.{d}.{d}", .{
        pin.bytes[0], pin.bytes[1], pin.bytes[2], pin.bytes[3],
    }) catch return error.FetchFailed;

    if (protocol == .tls) {
        // The root certificates and the time to judge them by. `Client.request`
        // is what usually loads them, and the connection is made before the
        // request here, so they are loaded first: `Connection.Tls.create` reads
        // both and asserts the time is set. `Client.request` then finds `now`
        // already set and does not read the certificates a second time.
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
        // Where the socket goes.
        .host = std.Io.net.HostName.init(written) catch return error.FetchFailed,
        .port = port,
        .protocol = protocol,
        // **The name, and not the address.** What the certificate is checked
        // against, and what the pool is keyed on.
        .proxied_host = std.Io.net.HostName.init(host) catch return error.FetchFailed,
        .proxied_port = port,
    }) catch return error.FetchFailed;
}

/// The first address in `checked` that can be written out as an IPv4 address.
fn firstIp4(checked: []const Resolver.Address) ?std.Io.net.Ip4Address {
    for (checked) |address| switch (address) {
        .ip4 => |ip4| return ip4,
        // An IPv4 address written as an IPv6 one is still that IPv4 address,
        // and `network.addressIsReachable` already reads it as one.
        .ip6 => |ip6| if (std.Io.net.Ip4Address.fromIp6(ip6)) |ip4| return ip4,
    };
    return null;
}

/// The port `uri` names, or the one its scheme fixes. Only the two schemes
/// `performNetFetch` accepts reach this, and it is read for a diagnostic
/// rather than for a socket.
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
    // The build goes through the daemon. A broker that quietly built without
    // one would be reaching the store some other way, which is not the act the
    // user approved.
    std.Io.Dir.accessAbsolute(io, a.daemon_socket, .{}) catch |err| {
        _ = diagnostic.note(diag, .{ .nix_daemon_unreachable = .{ .path = a.daemon_socket, .err = err } });
        return error.NixDaemonUnavailable;
    };

    var child_env = try ctx.env.clone(gpa);
    defer child_env.deinit();
    // `daemon` and not the socket path: a plain `daemon` reads the ordinary
    // socket, and `unix://<path>` names one directly, so the field is
    // honoured either way.
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
    // A write inside the workspace needs no approval at all, so an approval
    // for one must never become a way to reach it. This is the one place
    // that can tell the two apart, because the workspace root is part of
    // what the user read.
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

    // The objects go across before the ref moves, always. An object nothing
    // names is inert, and git removes it in its own time. A ref that names
    // an object which is not there is a repository the user cannot read.
    var moved: usize = 0;
    for (a.objects) |id| {
        const source = try objectPath(gpa, a.scratch_object_store, id);
        defer gpa.free(source);
        const target = try objectPath(gpa, a.project_object_store, id);
        defer gpa.free(target);

        std.Io.Dir.copyFileAbsolute(source, target, io, .{ .make_path = true }) catch |err| switch (err) {
            error.FileNotFound => {
                // The project may already hold it: git never writes an
                // object it can already read through the alternate, so an
                // object of an earlier apply is in the project and not in
                // the scratch store. That is the finished state this act
                // wants, so it is not a failure.
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

    // The old id is the old value of a compare and swap. git takes an empty
    // one to mean the ref must not exist, which is exactly what an empty
    // `old_id` says here.
    gpa.free(try runGit(gpa, io, ctx, a.repository, &.{ "update-ref", a.ref, a.new_id, a.old_id }, diag));

    return .{ .workspace_apply = .{
        .objects_moved = moved,
        .ref = try gpa.dupe(u8, a.ref),
        .new_id = try gpa.dupe(u8, a.new_id),
    } };
}

fn performModelSelect(
    gpa: std.mem.Allocator,
    ctx: Context,
    a: ModelSelect,
    diag: ?*?Diagnostic,
) PerformError!Result {
    // The roster is what the user offered this session. An approval to change
    // model is not an approval to reach a model that was never on the list, so
    // this is checked here and not by the caller.
    for (ctx.roster) |alias| {
        if (!std.mem.eql(u8, alias, a.to)) continue;
        return .{ .model_select = .{ .alias = try gpa.dupe(u8, a.to) } };
    }
    _ = diagnostic.note(diag, .{ .model_not_on_roster = a.to });
    return error.ModelNotOnRoster;
}

/// True when `path` is `root` itself or sits under it. Both must be
/// absolute. The separator check is what keeps `/home/ross/projects` from
/// reading as inside `/home/ross/project`.
fn isInside(path: []const u8, root: []const u8) bool {
    const trimmed = std.mem.trimEnd(u8, root, std.fs.path.sep_str);
    if (trimmed.len == 0) return true;
    if (!std.mem.startsWith(u8, path, trimmed)) return false;
    if (path.len == trimmed.len) return true;
    return path[trimmed.len] == std.fs.path.sep;
}

/// Where one object lives inside an object store: the first two characters
/// of its id name the directory, and the rest name the file.
fn objectPath(gpa: std.mem.Allocator, store: []const u8, id: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(gpa, "{s}{c}{s}{c}{s}", .{
        store,
        std.fs.path.sep,
        id[0..2],
        std.fs.path.sep,
        id[2..],
    });
}

/// An object id is hexadecimal, and is either a SHA-1 name or a SHA-256 one.
/// This id becomes a path, so a value that is not one of those two shapes is
/// never joined onto a store's own path.
fn checkObjectId(id: []const u8) PerformError!void {
    if (id.len != 40 and id.len != 64) return error.BadObjectId;
    for (id) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!is_hex) return error.BadObjectId;
    }
}

/// Run a program that is not git, read what it printed on standard output,
/// and give that back when it exited zero. Null when it did not, so a caller
/// names its own error for a failure of its own program.
///
/// Standard error is inherited rather than piped, on purpose. Only one pipe
/// is read, so this cannot deadlock the way two would, and whatever the
/// program says about a failure reaches the terminal the user is already
/// watching. `lib/chock-workspace/git.zig` reads both, and needs the
/// concurrency to do it; nothing here needs git's own stderr as a value.
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

/// `chock_proto.storage.Locked` is not `pub`, so no file outside that one
/// can name it. This reaches the same type through the return type of
/// `Storage.lock`, the same way `Broker.zig`'s own tests do.
const LockedHandle = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// Read the absolute path of an already open directory.
/// `std.testing.tmpDir` hands back a directory reached only through a
/// relative path, and every git call here needs an absolute one. Copies of
/// this function live in `lib/chock-workspace/git.zig` and two other files,
/// each with its own reason it cannot import another library's.
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

/// Run git at `cwd` and require it to exit zero. The trimmed standard output
/// comes back, owned by the caller.
fn gitOk(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    argv: []const []const u8,
) ![]u8 {
    var output = try git.run(gpa, testing.io, env, cwd, argv, null);
    defer output.deinit(gpa);
    // git says plenty on standard error while succeeding, so what it said is
    // read only when it also failed. **The failure carries it, and nothing
    // is written to the terminal.** This comparison is reached only after
    // git already exited non zero, and `expectEqualStrings` prints both
    // sides. Written out instead, the same words would land in the build log
    // of every passing run of this suite, and `zig build` reads any run step
    // that wrote to standard error as a failure.
    if (output.term != .exited or output.term.exited != 0) {
        try testing.expectEqualStrings("", output.stderr);
    }
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    return gpa.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

/// A fresh repository with one commit, plus an empty scratch directory
/// beside it for a session's own worktree and object store.
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
        // Chock's own checkout is a git repository and this scratch tree sits
        // inside it. Without a ceiling, git's upward search reaches it.
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

    /// Every object id the repository holds, one per line, in git's own
    /// order. The first half of "byte for byte unchanged".
    fn objectList(self: *const TestProject) ![]u8 {
        return gitOk(self.gpa, &self.env, self.root_path, &.{
            "cat-file", "--batch-all-objects", "--batch-check=%(objectname)",
        });
    }

    /// Every ref the repository has, HEAD included, and what each points at.
    /// The second half of "byte for byte unchanged".
    fn refList(self: *const TestProject) ![]u8 {
        return gitOk(self.gpa, &self.env, self.root_path, &.{ "show-ref", "--head" });
    }
};

/// A throwaway worktree with its own scratch object store, and one commit
/// made in it the way a sandboxed `git commit` makes one: every object goes
/// to the scratch store, and the project's own store is a read only
/// alternate.
const TestSession = struct {
    gpa: std.mem.Allocator,
    worktree: chock_workspace.worktree.Worktree,
    /// The environment a git call in this worktree needs on the host. The
    /// same two variables `Worktree.gitEnv` names, with host paths instead of
    /// the sandbox paths, since nothing here runs inside a sandbox.
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

    /// Write `contents` at `rel_path` in the worktree, stage it, commit it,
    /// and give back the id of the commit. Every object this makes lands in
    /// the scratch store alone.
    fn commit(self: *const TestSession, rel_path: []const u8, contents: []const u8, message: []const u8) ![]u8 {
        const path = try std.fs.path.join(self.gpa, &.{ self.worktree.path, rel_path });
        defer self.gpa.free(path);
        try writeFileAbsolute(testing.io, path, contents);
        self.gpa.free(try gitOk(self.gpa, &self.env, self.worktree.path, &.{ "add", rel_path }));
        self.gpa.free(try gitOk(self.gpa, &self.env, self.worktree.path, &.{ "commit", "-m", message }));
        return gitOk(self.gpa, &self.env, self.worktree.path, &.{ "rev-parse", "HEAD" });
    }
};

/// A policy that asks about every one of the eight actions, so every test
/// below goes through a real question and a real answer.
const ask_every_action: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\        },
    \\    },
    \\}
;

/// A `Broker.Waiter` that answers the one open request with `decision` the
/// first time the broker gives control away. It never sleeps.
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
        // Nothing cancels these tests. See `Broker.Waiter.Wake`.
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

/// Ask for `ask` over a real in memory log, answer it with `decision`, and
/// give back what `run` made of it. This is the whole approval flow driven end
/// to end, with a test standing in for the client that answers.
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

/// The parts of an `Ask` these tests do not vary.
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
    // The agent's commit lives in a scratch object store the project cannot
    // see, and this act is the only thing that carries it across: the broker
    // moves the objects on the host and then moves the ref, with the agent's
    // process nowhere near either half.
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

    // The project has never seen this commit. Without this the test could
    // pass over a repository that already held everything.
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
    }, null);

    // The description named real work: a commit of one new file writes at
    // least a blob, a tree, and the commit itself.
    try testing.expect(apply.objects.len >= 3);
    try testing.expect(apply.old_id.len > 0);
    try testing.expect(std.mem.indexOf(u8, apply.diff, "the agent wrote this") != null);

    var attempt = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .workspace_apply = apply }));
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expectEqual(Broker.Outcome.approved_by_user, attempt.done.outcome);
    try testing.expectEqual(apply.objects.len, attempt.done.result.workspace_apply.objects_moved);
    try testing.expectEqualStrings(new_id, attempt.done.result.workspace_apply.new_id);

    // Every object the request listed is now readable in the user's own
    // repository, with no alternate and no scratch store in the environment
    // at all. `git cat-file -e` fails when the object is not there.
    for (apply.objects) |id| {
        gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "cat-file", "-e", id }));
    }

    // The ref moved to exactly the id the user approved.
    const head_now = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(head_now);
    try testing.expectEqualStrings(new_id, head_now);

    // And the content the agent wrote is what the ref now names, read out of
    // the user's own repository.
    const shown = try gitOk(gpa, &project.env, project.root_path, &.{ "show", "refs/heads/main:agent.txt" });
    defer gpa.free(shown);
    try testing.expectEqualStrings("the agent wrote this", shown);
}

test "a refused workspace.apply leaves the user's repository byte for byte unchanged" {
    // Both halves, because either one alone is half the property. A broker
    // that moved the objects and then refused to move the ref would leave
    // the refs identical and the object list longer, and a test that read
    // only the refs would call that unchanged.
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
    }, null);
    // The act really had something to do. A description of nothing would
    // leave the repository unchanged whatever the broker did.
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

    // The work is still where it was, in the session's own scratch store, so
    // a refusal loses nothing and leaves nothing behind in the project. The
    // scratch store goes away with the worktree.
    for (apply.objects) |id| {
        gpa.free(try gitOk(gpa, &session.env, session.worktree.path, &.{ "cat-file", "-e", id }));
    }
}

test "a workspace.apply nobody can answer expires at once, and the repository is unchanged" {
    // **This is exactly how `chock run` asks.** `Loop.run` holds the
    // exclusive lock on the session log for the whole session and `src/run.zig`
    // takes it again to ask this, so while the question is open nothing else
    // can append an answer to the log. Waiting therefore spends a person's
    // time and can change nothing, so the timeout is zero and the unanswered
    // request is a refusal.
    //
    // Driven with a `SystemWaiter`, the real clock, and no answerer at all:
    // a test waiter that answers would prove the opposite of the point.
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
        // The ref `src/run.zig` builds: never a branch of the user.
        .ref = "refs/chock/01SESSION",
        .new_id = new_id,
    }, null);
    try testing.expect(apply.objects.len >= 3);
    // A ref that does not exist yet, which git is told the act must find
    // absent.
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
    // The other side of the test above, and the only way to say yes in a
    // `chock run`: a rule in `chock.zon`, which stays beyond the agent's reach.
    // Nothing answers here either, and nothing has to: the policy answers first
    // and no question is ever written.
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

    // The agent's own commit is now readable in the user's repository, with
    // no scratch store in the environment at all.
    for (apply.objects) |id| {
        gpa.free(try gitOk(gpa, &project.env, project.root_path, &.{ "cat-file", "-e", id }));
    }
    const ref_now = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/chock/01SESSION" });
    defer gpa.free(ref_now);
    try testing.expectEqualStrings(new_id, ref_now);

    // And the user's own branch never moved, which is what keeps a session
    // from rewriting the working tree under somebody.
    const main_now = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(main_now);
    try testing.expect(!std.mem.eql(u8, main_now, new_id));
}

test "an action names its effect, and the effect is a diff and not a command" {
    // A user approves what will happen, never a shell line. This test pins the
    // property in the two places it lives: in the shape of the types, which is
    // what stops a future caller, and in what the eight actions actually
    // render.
    const gpa = testing.allocator;

    // First: the shape. `Ask` is the only way into `run`, and it has nowhere
    // to put a summary or a detail of its own, so both always come from the
    // action. A caller cannot hand the user a command string even by trying.
    try testing.expect(!@hasField(Ask, "summary"));
    try testing.expect(!@hasField(Ask, "detail"));

    // And no action payload has a field that could hold one. The comptime
    // block at the end of this file fails the build over the same list; this
    // repeats it as a fact a reader of the tests can see.
    const forbidden = [_][]const u8{ "command", "argv", "args", "cmd", "shell", "script" };
    inline for (@typeInfo(Action).@"union".fields) |field| {
        inline for (@typeInfo(field.type).@"struct".fields) |payload_field| {
            for (forbidden) |bad| {
                try testing.expect(!std.ascii.eqlIgnoreCase(payload_field.name, bad));
            }
        }
    }

    // Second: what each one renders. All eight, in order, each built with an
    // effect a user could read and act on.
    const diff =
        \\diff --git a/parser.zig b/parser.zig
        \\@@ -1 +1 @@
        \\-const limit = 4;
        \\+const limit = 8;
    ;
    const cases = [_]struct {
        action: Action,
        name: []const u8,
        /// Substrings the detail must carry: the effect itself.
        effect: []const []const u8,
        /// A command a lazier design would have shown instead.
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

    // All eight, and nothing else.
    try testing.expectEqual(@as(usize, 8), @typeInfo(Action).@"union".fields.len);
    try testing.expectEqual(cases.len, @typeInfo(Action).@"union".fields.len);

    for (cases) |case| {
        try testing.expectEqualStrings(case.name, case.action.name());

        const summary = try case.action.summary(gpa);
        defer gpa.free(summary);
        const detail = try case.action.detail(gpa);
        defer gpa.free(detail);

        // One line for a list, and it says what happens, not what runs.
        try testing.expect(summary.len > 0);
        try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, summary, '\n'));
        try testing.expect(std.mem.indexOf(u8, summary, case.never) == null);

        // The whole effect, every part of it, and never the command.
        // **Each failure carries the detail it read.** A block below is
        // reached only when the comparison in it cannot hold, and
        // `expectEqualStrings` prints both sides, so a reader sees the whole
        // detail beside the part that was wrong about it. See `runGit` above
        // for why nothing here is written to the terminal.
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
    // The diff a user approves covers named paths. A broker that ran a plain
    // `git commit --all` would carry in whatever else the agent changed
    // after the question was asked, which is a different act from the one
    // that was approved.
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

    // A bare repository beside the project stands in for the remote. No
    // network is involved, and none is needed: what this pins is which id
    // lands on which ref.
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
    // The user approved one ref move, from one id to another. If the remote
    // moved between the question and the answer, the act the broker would
    // perform is not the act the user approved, so it does not happen.
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

    // A stale lease: the request says the remote is at an id it never was.
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

    // The remote is exactly where it was. The push did not happen.
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

    // A request that names the wrong commit is refused, whatever the user
    // said: the branch the user read about is not the branch that is there.
    try testing.expectError(error.GitFailed, askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .git_branch_delete = .{
        .repository = project.root_path,
        .branch = "spike",
        .points_at = "0123456789012345678901234567890123456789",
        .merged_into = "refs/heads/main",
    } })));
    const still_there = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/spike" });
    defer gpa.free(still_there);
    try testing.expectEqualStrings(points_at, still_there);

    // The same request, naming where the branch actually is, deletes it.
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
    // The old bytes are part of the effect, read off the disk rather than
    // taken on trust from the caller.
    try testing.expectEqualStrings("the old bytes\n", write.previous.?);

    var attempt = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .file_write = write }));
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expectEqual(@as(usize, "the new bytes\n".len), attempt.done.result.file_write.bytes_written);

    const landed = try std.Io.Dir.cwd().readFileAlloc(io, outside, gpa, .limited(4096));
    defer gpa.free(landed);
    try testing.expectEqualStrings("the new bytes\n", landed);

    // A path inside the workspace is refused. A write there needs no
    // approval at all, so an approval for one must never become a way to
    // reach it.
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
    // "net.fetch for one host". The host is what the user read and what the
    // user approved, so a URL that names a different one is not the act that
    // was approved, whatever the URL says.
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

    // A scheme this broker cannot fetch is refused too, rather than handed
    // to something that might understand it.
    try testing.expectError(error.UrlNotUsable, askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .net_fetch = .{
        .host = "docs.example.invalid",
        .url = "file:///home/ross/.ssh/id_ed25519",
    } })));
}

test "nix.build refuses when nothing is listening on the daemon socket" {
    // The build goes through the daemon, and the sandbox never has that
    // socket. A broker that quietly built without it would be reaching the
    // store some other way, which is a different act.
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
    // The roster is what the user offered the session. An approval to change
    // model is not an approval to reach a model that was never on the list.
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
    // `Attempt` keeps the two apart on purpose. A refusal is a decision the
    // broker made and recorded; an error is the act failing while it ran.
    //
    // The second half is what `run`'s own `if (!outcome.permits())` line
    // decides, and it holds for all eight, because that line is above the
    // switch in `perform` and reads only the outcome. `model.select` is what
    // proves it here, because it is the one act whose failure needs nothing
    // on the machine set up: an alias the roster does not name makes
    // `perform` return `error.ModelNotOnRoster`, so a `run` that performed a
    // refused act would come back as that error instead of as a refusal.
    // Reading the outcome alone does not pin this, and an earlier version of
    // this test read only the outcome and did not catch it.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    // An empty roster refuses every selection, so `perform` cannot succeed.
    const ctx = Context{ .env = &project.env, .roster = &.{} };
    const ask = testAsk(.{ .model_select = .{ .from = "main", .to = "review" } });

    const attempt = try askAndAnswer(gpa, io, .refused_by_user, ctx, ask);
    try testing.expect(attempt == .refused);
    try testing.expectEqual(Broker.Outcome.refused_by_user, attempt.refused);

    // And an expired request is a refusal too, with its own name kept.
    const expired = try askAndAnswer(gpa, io, .expired, ctx, ask);
    try testing.expect(expired == .refused);
    try testing.expectEqual(Broker.Outcome.expired, expired.refused);

    // The same act, approved, does reach `perform` and does fail there. This
    // is what makes the two refusals above facts about `run` not calling
    // `perform`, rather than facts about `perform` happening to succeed.
    try testing.expectError(
        error.ModelNotOnRoster,
        askAndAnswer(gpa, io, .approved_by_user, ctx, ask),
    );
}

// The effect and never a command, enforced by the build rather than by a
// reviewer. See this file's own top comment.
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
}

test "the model a refused selection named reaches the caller, and no longer only a terminal" {
    // The point of the whole change. `error.ModelNotOnRoster` says a
    // selection was refused. Only the diagnostic says which alias the model
    // asked for, which is the fact a person needs to see, and before this the
    // broker printed it to the terminal and told the caller nothing.
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
    // The outer optional is what lets a caller opt out. The testing allocator
    // fails this test if the refusal leaks a copy nobody asked for.
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
    // A second module of this library, through the same slot: a caller holds
    // one diagnostic and reads whichever half of the broker answered.
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
    // **Two properties, and losing either one is silent.** A header with no
    // version leaves a site operator unable to say which Chock hit them. A
    // token that carried the version would stop matching every `robots.txt`
    // group ever written for `chock`, and the file would go on being fetched
    // and stop being obeyed.
    //
    // Mutation check: write `user_agent = chock_version.text` and the first
    // assertion fails; write `product_token = "chock/" ++ chock_version.text`
    // and the second fails.
    try testing.expect(std.mem.startsWith(u8, user_agent, product_token ++ "/"));
    try testing.expectEqualStrings("chock", product_token);

    // The number really is this build's own, and not a second copy somebody
    // has to remember to edit. `src/main.zig` is where it is pinned against
    // `build.zig.zon` itself.
    try testing.expect(chock_version.text.len != 0);
    try testing.expectEqualStrings(product_token ++ "/" ++ chock_version.text, user_agent);
}
