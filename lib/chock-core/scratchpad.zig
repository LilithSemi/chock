//! The session scratchpad: a working directory for files that are not the
//! project, and the read only directory beside it that background task output
//! lands in.
//!
//! ## What it is for
//!
//! Intermediate output, a script an agent wrote to answer one question, a log
//! it wants to grep. None of that belongs in the project: scratch inside the
//! workspace lands in the diff, reaches `workspace.apply`, and turns up in the
//! user's repository, which is the same reason `lib/chock-core/cache.zig` is
//! not there either.
//!
//! ```
//! <temp>/chock/<session id>/scratch/   read and write, the agent's own
//! <temp>/chock/<session id>/tasks/     read only, the harness writes it
//! <temp>/chock/<session id>/agents/    one subdirectory per subagent
//! ```
//!
//! Inside the sandbox the same two directories are `sandbox_dir` and
//! `lib/chock-core/tasks.zig`'s own `sandbox_dir`, both under `/run/chock`,
//! which `lib/chock-sandbox/Sandbox.zig` keeps for Chock's own paths. **On a
//! build that can move no path they appear at the host paths above instead**:
//! see `sandboxDirFor`.
//!
//! ## The split: notes here, temporary files in a capped area
//!
//! There is a third directory inside the sandbox, `tmp_sandbox_dir`, and it has
//! **no host directory at all**. It is a tmpfs with a hard cap on it, mounted
//! for one tool call and gone when that call ends: see
//! `lib/chock-sandbox/linux/namespace.zig`'s own `Scratch` for the measurements
//! and `lib/chock-sandbox/linux/rlimits.zig`'s own `default_scratch_bytes` for
//! why a cap can only ever be per call.
//!
//! **`TMPDIR` points at that capped area, and `CHOCK_SCRATCHPAD` points here.**
//! The reason the two are separate is that they want opposite lifetimes:
//!
//! * A temporary file is what fills a disk, and it is exactly what nothing
//!   needs after the call. So it belongs in an area that can be capped.
//! * A note is what one call leaves for the next one, and for a parent reading
//!   a child's answer. So it belongs in a bind mount of a host directory, which
//!   survives the call. A capped area here would come up empty every call and
//!   take the handoff away.
//!
//! **This changes an earlier decision.** That one said "point `TMPDIR` at the
//! session's scratchpad", and `TMPDIR` now names the capped area beside it
//! instead. The fault it fixed stays fixed, because `TMPDIR` still names a path
//! the sandbox really mounts; what changes is that a file written through
//! `TMPDIR` no longer survives the call that wrote it. `CHOCK_SCRATCHPAD` is
//! what an agent writes a note through, and it is named in the `run_command`
//! description so an agent does not have to guess.
//!
//! ## In the temp directory, and that is a security property
//!
//! It exists for the run and no longer. The other two writable surfaces
//! outside the workspace both persist: the toolchain cache is per project and
//! kept, and the knowledgebase is per project and kept on purpose. **Both are
//! channels that outlive the sandbox.** A scratchpad is not, so nothing an
//! agent leaves here reaches the next session, and it is the right home for
//! anything with no reason to persist. A thing that does not survive cannot be
//! a persistence mechanism.
//!
//! Keyed by session and not by project, for the same reason: two sessions of
//! one project share nothing here.
//!
//! ## It fixes a fault already measured
//!
//! A dev shell exports `TMPDIR=/tmp/nix-shell.XXXX`, a host path the sandbox
//! does not mount, and `src/run.zig`'s own `sandboxEnvironment` copies the dev
//! shell's variables into the sandbox. A red team session then measured this
//! inside a real tool call:
//!
//! ```
//! make: TMPDIR value /tmp/nix-shell.qHnEsN: No such file or directory
//! ```
//!
//! `environment` below points `TMPDIR` at the scratchpad, which is what the
//! variable is for. **Chock's own answer wins**, the same rule
//! `cache.environment` keeps for `HOME`: two entries of one name is undefined
//! in POSIX, and the dev shell's value names a path that is not in the mount
//! tree at all.
//!
//! **The sandbox's `TMPDIR` and the harness's own are different things.**
//! `tools.stageContent` reads `TMPDIR` off the host environment to stage a
//! file on the host, before any sandbox exists. This file never touches that
//! one: `environment` builds `sandbox.Config.env`, which is read by the
//! program inside the sandbox and by nothing else.
//!
//! ## The visibility rule, which is the part with teeth
//!
//! * A subagent sees its own and nothing else.
//! * The main agent sees all of them.
//! * **Siblings see nothing of each other.**
//!
//! The third one is the one to enforce carefully. Two subagents that share a
//! directory have a channel the log does not record, and the log is the truth
//! about what happened in a session. Coordination through a filesystem is
//! coordination nobody can replay, review, or sign.
//!
//! A parent reading a child's scratchpad is fine: the parent spawned it, holds
//! its budget slice, and already reads its log. A child reading the parent's is
//! not, because it would learn things it was not told.
//!
//! `mayRead` states the rule and `leafFor` builds the path, so a mount tree is
//! never built from a path some caller joined by hand. A child directory is
//! made by the child itself, at the path its parent named:
//! `lib/chock-core/subagent.zig`'s own `childDir` joins the parent's directory
//! to `leafFor`, and `chock run --scratchpad` is what the child is given.
//!
//! **The main agent's files sit in a subdirectory of their own.** Beside the
//! child directories is one level cheaper and lets a child identifier collide
//! with a file the main agent wrote; `scratch/`, `tasks/` and `agents/` cannot.

const std = @import("std");
const sandbox = @import("chock-sandbox");

const diagnostic = @import("diagnostic.zig");
/// Why a piece of the loop's own scaffolding could not be made or kept. One
/// type for the whole module: see `chock-core/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
/// Where a fault goes, and who owns the path it names. **Every path this file
/// puts in a message is built in a stack buffer of the frame that built it**,
/// so the message keeps a copy and the caller says who holds it.
pub const Sink = diagnostic.Sink;
/// Build a `Sink` from an allocator and the slot a caller passed. Release the
/// message with that same allocator: see `Diagnostic.deinit`.
pub const sinkOf = diagnostic.sinkOf;
const cache = @import("cache.zig");

/// Where the agent writable scratchpad is mounted inside the sandbox **on a
/// build that can move a path**. See `sandboxDirFor`, which is what a caller
/// asks.
pub const sandbox_dir = "/run/chock/scratch";

/// Where the scratchpad of the session directory `host_dir` appears inside the
/// sandbox.
///
/// **Two answers, one per platform.** A build that moves a path puts it at
/// `sandbox_dir`, the same path in every session. macOS moves no path, so the
/// scratchpad appears where it really is and the mount becomes a rule. See
/// `lib/chock-workspace/layout.zig`, which is the same decision for the
/// workspace.
///
/// `host_dir` is the `scratch/` directory itself and not the session directory
/// above it, because that is the directory the mount carries.
pub fn sandboxDirFor(host_dir: []const u8) []const u8 {
    return if (sandbox.expresses.moved_paths) sandbox_dir else host_dir;
}

/// Where the capped temporary area is mounted inside the sandbox.
///
/// **No host directory answers to this path.** It is a tmpfs the sandbox mounts
/// for one tool call, sized by `Sandbox.Limits.scratch_bytes`, and the kernel
/// takes it away with the mount namespace when the call ends. See this file's
/// own top comment for why the notes and the temporary files are two places.
///
/// A build with no `sandbox.expresses.scratch_area` never mounts one and never
/// names this path: see `tempAreaFor`.
pub const tmp_sandbox_dir = "/run/chock/tmp";

/// The three directories one session's scratchpad holds, relative to the
/// session's own directory on the host. `makeLayout` builds them, and nothing
/// else may build a path below the scratchpad from parts.
pub const scratch_leaf = "scratch";
pub const tasks_leaf = "tasks";
pub const agents_leaf = "agents";

/// Which directory `TMPDIR` names for one tool call.
///
/// **A capped area is not always available, and the caller decides.** A cap
/// comes out of the same budget the memory ceiling names, because a tmpfs page
/// is charged to the cgroup, so a caller whose limits fail
/// `Sandbox.Limits.scratchFitsUnderMemory` must not be given one: a full area
/// under those limits arrives as a bare `SIGKILL` rather than as `ENOSPC`,
/// which is two different faults reading the same way. `tempAreaFor` is that
/// decision, and it is the only place it is made.
pub const TempArea = enum {
    /// `TMPDIR` names `tmp_sandbox_dir`, a tmpfs of its own with a cap on it.
    /// What every ordinary call gets.
    capped,
    /// `TMPDIR` names `sandbox_dir`, the scratchpad itself, which is what Chock
    /// did before the two were split. Nothing bounds how much a call writes
    /// into it while that call runs: `max_bytes` is measured **between** calls.
    ///
    /// **The `run_command` description is written for the other case**, and
    /// says a file under `TMPDIR` goes when the call does. Under this one it
    /// stays. The description is one compiled string and cannot branch, and no
    /// caller in this project reaches this case today, so the cost is a
    /// sentence that is too cautious rather than one that is wrong in a
    /// dangerous direction: an agent that treats a surviving file as gone
    /// writes it twice, and one that treated a gone file as surviving would
    /// lose work.
    scratchpad,
};

/// Which area a call with these limits may point `TMPDIR` at.
///
/// **Narrowing the memory ceiling and leaving the cap alone is what this
/// catches.** `Limits.narrow` lets a caller lower one number without the other,
/// so the pairing has to be asked about per call rather than trusted once.
///
/// **A build with no cap mechanism at all answers first, and it does not ask
/// for one.** An ordinary user on macOS cannot mount a filesystem, so there is
/// no capped area to give: `sandbox.expresses.scratch_area` says so, and
/// `darwin/driver.zig`'s own `expressibleOn` refuses a caller that asks anyway
/// rather than handing back an uncapped area and saying nothing. `chock doctor`
/// carries the same fact as its `disk cap tmpfs` row, so the limit reads
/// `unsupported` to a person instead of reading as one that holds.
pub fn tempAreaFor(limits: sandbox.Sandbox.Limits) TempArea {
    if (!sandbox.expresses.scratch_area) return .scratchpad;
    return if (limits.scratchFitsUnderMemory()) .capped else .scratchpad;
}

/// The two names `environment` writes, so it can take an earlier answer out of
/// the list rather than leave two entries of one name behind.
///
/// `TMPDIR` is the name every tool that wants a temporary directory already
/// reads: `make`, `gcc`, `git`, and the C library's own `tmpfile`. A tool
/// specific name there would be a name to keep in step with a program Chock
/// does not ship.
///
/// **`CHOCK_SCRATCHPAD` is Chock's own name for Chock's own directory**, which
/// is the opposite case: no existing program looks for this path, and the only
/// reader is an agent that has to be told where a note survives the call. Left
/// unnamed, an agent would write its notes through `TMPDIR` and find them gone
/// on the next call, which is the handoff the scratchpad exists for.
pub const variable_names = [_][]const u8{ "TMPDIR", "CHOCK_SCRATCHPAD" };

/// What `TMPDIR` names for a call whose scratchpad appears at `dir`.
///
/// A capped area is a mount of the sandbox's own and is at a fixed path; the
/// other case is the scratchpad itself, wherever that turns out to be.
pub fn tempDirFor(area: TempArea, dir: []const u8) []const u8 {
    return switch (area) {
        .capped => tmp_sandbox_dir,
        .scratchpad => dir,
    };
}

/// How much one session's scratchpad may hold before it is emptied.
///
/// Half a gibibyte. Ephemeral does not mean small: a runaway agent can still
/// fill a disk, and a full disk is a fault for everything on the machine and
/// not only for Chock. This is smaller than the toolchain cache's own two
/// gibibytes on purpose, and for two reasons. A cache holds a whole toolchain
/// state and is reused for months; a scratchpad holds one session's working
/// files. And a temp directory is a tmpfs on many machines, sized from the
/// memory, so a session that assumed gigabytes there would take the memory
/// away from everything else running.
///
/// The task output directory is bounded separately, by construction, and it is
/// never emptied: see `lib/chock-core/tasks.zig`. The capped area is bounded by
/// the kernel itself, and this number has nothing to do with it: see
/// `tmp_sandbox_dir`.
///
/// **Since the split this bounds notes and nothing else**, which is why it is
/// still measured between calls rather than enforced during one. A note is
/// written deliberately, one at a time; what a runaway agent really fills a
/// disk with is a build's temporary files, and those now land in an area the
/// kernel refuses a write to the moment it is full.
pub const max_bytes: u64 = 512 * 1024 * 1024;

/// What one scratchpad holds. The same walk the toolchain cache is measured
/// with, and deliberately the same type: a second copy of "count the bytes
/// below a directory, and stop once the answer is decided" is how two numbers
/// quietly stop agreeing.
pub const Size = cache.Size;

/// What a tool call does about a scratchpad of this size. See `verdictFor`.
pub const Verdict = enum {
    /// Under the bound: the call runs and the scratchpad keeps what is in it.
    keep,
    /// Over the bound: `scratch/` is emptied, the agent is told in the result
    /// of the same call, and the call then runs.
    empty,
};

/// Whether a scratchpad this size is kept or emptied.
///
/// **Emptying is the answer, and it is a decision.** The alternative, refusing
/// every `run_command` call while the scratchpad is over its bound, takes away
/// the one tool that could delete anything: `write_file` and `edit_file` write
/// in the workspace and nowhere else, so a refused session could never get
/// back under the bound and could do no other work either.
///
/// It is honest here for a reason it is not honest everywhere. A scratchpad is
/// already promised to be gone when the run ends, so nothing in it is a record
/// anybody may rely on. **`tasks/` is not emptied**, because a task output file
/// is exactly such a record: see `clearScratch`.
///
/// The agent is told, in the result of the very call that emptied it, so this
/// is never a directory that quietly loses its contents.
pub fn verdictFor(size: Size) Verdict {
    return if (size.bytes > max_bytes) .empty else .keep;
}

/// Which agent a scratchpad belongs to.
///
/// A `union(enum)` and not an optional identifier, so a caller states which of
/// the two cases it means and `mayRead` can switch on both.
pub const Agent = union(enum) {
    /// The session's own agent, the one a user started.
    main,
    /// A subagent, named by its own session identifier. See
    /// `lib/chock-core/subagent.zig`'s own `childDir`, which is what joins one
    /// of these to a parent's own directory.
    child: []const u8,
};

/// Whether `viewer` may read the scratchpad of `owner`. See this file's own
/// top comment for why the sibling case is the one that matters.
pub fn mayRead(viewer: Agent, owner: Agent) bool {
    return switch (viewer) {
        // The parent spawned every child, holds its budget slice, and already
        // reads its log.
        .main => true,
        .child => |viewer_id| switch (owner) {
            // A child reading the parent's would learn things it was not told,
            // which is the opposite of the narrowing a spawn is meant to be.
            .main => false,
            // Its own, and no other child's. Two children that could read one
            // another have a channel the session log does not record.
            .child => |owner_id| std.mem.eql(u8, viewer_id, owner_id),
        },
    };
}

pub const LeafError = error{
    /// The child identifier is not one `src/session.zig`'s own `newId` makes.
    /// Refused before it is joined to a path, because a value that reached a
    /// path unchecked is a path traversal.
    BadChildId,
};

/// Where `agent`'s own scratchpad sits, relative to the session directory.
/// Caller owns the result.
///
/// The one place a path below the session directory is built from an
/// identifier. A caller that joined `agents_leaf` and an identifier by hand
/// would be the caller that forgot to check the identifier.
pub fn leafFor(
    allocator: std.mem.Allocator,
    agent: Agent,
) (std.mem.Allocator.Error || LeafError)![]u8 {
    return switch (agent) {
        .main => allocator.dupe(u8, scratch_leaf),
        .child => |id| {
            if (!isPlainName(id)) return error.BadChildId;
            return std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ agents_leaf, id, scratch_leaf });
        },
    };
}

/// True when `name` holds only characters a directory name may have here:
/// letters, digits, `-` and `_`. No `/`, no `.`, so no `..` and no absolute
/// path can ever be built from one.
fn isPlainName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |character| {
        const ok = std.ascii.isAlphanumeric(character) or character == '-' or character == '_';
        if (!ok) return false;
    }
    return true;
}

/// The environment `base` becomes for a call whose scratchpad appears at `dir`
/// inside the sandbox: every entry of `base` that does not name one of
/// `variable_names`, and then the two `area` decides.
///
/// **Every entry of the result is owned by `allocator`**, for the reason
/// `cache.environment` gives, and `cache.freeEnvironment` releases it.
///
/// **Chock's own answer wins**, which is the whole fix. See this file's own top
/// comment for the `make` failure the dev shell's own `TMPDIR` caused.
pub fn environment(
    allocator: std.mem.Allocator,
    base: []const []const u8,
    area: TempArea,
    dir: []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var entries: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (entries.items) |entry| allocator.free(entry);
        entries.deinit(allocator);
    }

    for (base) |entry| {
        if (namesAScratchVariable(entry)) continue;
        try entries.append(allocator, try allocator.dupe(u8, entry));
    }
    try entries.append(allocator, try std.fmt.allocPrint(
        allocator,
        "TMPDIR={s}",
        .{tempDirFor(area, dir)},
    ));
    try entries.append(allocator, try std.fmt.allocPrint(allocator, "CHOCK_SCRATCHPAD={s}", .{dir}));
    return entries.toOwnedSlice(allocator);
}

/// See `cache.freeEnvironment`. Re-exported here so a caller that holds one of
/// these results reaches the release beside the builder that made it.
pub const freeEnvironment = cache.freeEnvironment;

/// True when this `KEY=VALUE` entry names one of `variable_names`.
fn namesAScratchVariable(entry: []const u8) bool {
    const equals = std.mem.indexOfScalar(u8, entry, '=') orelse return false;
    const key = entry[0..equals];
    for (variable_names) |name| {
        if (std.mem.eql(u8, key, name)) return true;
    }
    return false;
}

pub const LayoutError = error{
    /// A directory this scratchpad needs could not be made. Pass a
    /// `Diagnostic` to learn which one and why, because a caller can act on
    /// "read only filesystem" and cannot act on this name alone.
    ScratchpadDirectoryUnwritable,
};

/// Build `dir_path` and the three directories inside it.
///
/// **One owner of the layout.** `src/session.zig` decides where a session's
/// scratchpad lives, and this decides what is in it, so a directory the
/// environment names can never be missing from the tree the sandbox mounts. A
/// `make` given a `TMPDIR` that does not exist fails in exactly the way this
/// whole file exists to end.
pub fn makeLayout(io: std.Io, dir_path: []const u8, diag: ?Sink) LayoutError!void {
    try makeDirAll(io, dir_path, diag);
    inline for (.{ scratch_leaf, tasks_leaf, agents_leaf }) |leaf| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ dir_path, leaf }) catch
            return error.ScratchpadDirectoryUnwritable;
        try makeDirAll(io, path, diag);
    }
}

/// True when `dir_path` is already a directory on the host.
pub fn exists(io: std.Io, dir_path: []const u8) bool {
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{}) catch return false;
    dir.close(io);
    return true;
}

/// How much the agent writable half of `dir_path` holds.
///
/// **Only `scratch/`.** `tasks/` is the harness's own, it is bounded by
/// construction, and it is never emptied, so counting it here would empty the
/// agent's files because of records the agent did not write.
pub fn measureScratch(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
    stop_at: u64,
) Size {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ dir_path, scratch_leaf }) catch return .{};
    return cache.measure(allocator, io, path, stop_at);
}

/// Empty `scratch/` and answer what went. The directory itself stays, so the
/// next tool call has somewhere to write.
///
/// **`tasks/` is not touched.** A task output file is a record of what a
/// command produced, and a record something else can delete is not a record.
pub fn clearScratch(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
    diag: ?Sink,
) LayoutError!Size {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ dir_path, scratch_leaf }) catch
        return error.ScratchpadDirectoryUnwritable;

    const went = cache.measure(allocator, io, path, std.math.maxInt(u64));

    var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true }) catch return went;
    {
        defer dir.close(io);

        // The names first, then the deletes: deleting while a directory is
        // walked is undefined on more than one filesystem. The same shape
        // `cache.clear` and `memory.clear` both use, for the same reason.
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |name| allocator.free(name);
            names.deinit(allocator);
        }

        var it = dir.iterate();
        while (it.next(io) catch null) |entry| {
            const owned = allocator.dupe(u8, entry.name) catch continue;
            names.append(allocator, owned) catch {
                allocator.free(owned);
                continue;
            };
        }
        for (names.items) |name| dir.deleteTree(io, name) catch continue;
    }

    try makeDirAll(io, path, diag);
    return went;
}

/// Remove the whole session scratchpad, task output and all.
///
/// **This is what makes "gone when the run ends" true.** A temp directory is
/// emptied by the machine at some point of its own choosing, which is not the
/// same promise: a session that ended an hour ago must not still have its files
/// on disk. Best effort, and never fatal: a session that has already produced
/// its answer must not fail because a directory would not delete.
pub fn remove(io: std.Io, dir_path: []const u8) void {
    var parent_dir = std.Io.Dir.openDirAbsolute(io, std.fs.path.dirname(dir_path) orelse return, .{}) catch return;
    defer parent_dir.close(io);
    parent_dir.deleteTree(io, std.fs.path.basename(dir_path)) catch {};
}

/// **`path` is borrowed for the length of this call only.** Every caller
/// builds it in a buffer of its own frame, so `notePath` copies it into the
/// sink's own allocator.
fn makeDirAll(io: std.Io, path: []const u8, diag: ?Sink) LayoutError!void {
    makeDirAllInner(io, path) catch |err| {
        diagnostic.notePath(diag, .scratchpad_directory_not_made, path, err);
        return error.ScratchpadDirectoryUnwritable;
    };
}

/// The same recursive create `src/session.zig` makes for a session directory.
/// Here rather than there because this file owns the layout, and a second
/// spelling of the layout is how two paths quietly stop agreeing.
fn makeDirAllInner(io: std.Io, path: []const u8) !void {
    if (path.len == 0) return;
    std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            try makeDirAllInner(io, parent);
            std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |second| switch (second) {
                error.PathAlreadyExists => return,
                else => return second,
            };
        },
        else => return err,
    };
}

const testing = std.testing;
const tasks = @import("tasks.zig");

test "the scratchpad environment points TMPDIR at a path the sandbox mounts" {
    // The whole fix in one assertion. A dev shell states
    // `TMPDIR=/tmp/nix-shell.XXXX`, a host path the sandbox does not mount,
    // and `make` answered "No such file or directory" on exactly that.
    const allocator = testing.allocator;

    const built = try environment(allocator, &.{}, .capped, sandbox_dir);
    defer freeEnvironment(allocator, built);

    try testing.expectEqual(@as(usize, 2), built.len);
    try testing.expectEqualStrings("TMPDIR=/run/chock/tmp", built[0]);
    try testing.expectEqualStrings("CHOCK_SCRATCHPAD=/run/chock/scratch", built[1]);
}

test "a scratchpad appears under the runtime prefix, or at its own path where no path can move" {
    // **The macOS blocker, in one assertion.** `darwin/driver.zig`'s own
    // `expressibleOn` refuses a bind whose target differs from its source, and
    // `chock doctor` on the Darwin box named this very directory,
    // `/run/chock/scratch`, as why a whole tool call was refused. Measured on
    // 2026-08-25.
    //
    // Mutation check: answer `sandbox_dir` in both arms of `sandboxDirFor` and
    // the second half fails on Darwin; answer `host_dir` in both and the first
    // half fails on Linux.
    const allocator = testing.allocator;
    const host_dir = "/somewhere/on/the/host/scratch";

    if (sandbox.expresses.moved_paths) {
        try testing.expectEqualStrings(sandbox_dir, sandboxDirFor(host_dir));
    } else {
        try testing.expectEqualStrings(host_dir, sandboxDirFor(host_dir));
    }

    // And both variables name whatever that answer was, so an agent told where
    // its notes go is told a path this build really mounts.
    const inside = sandboxDirFor(host_dir);
    const built = try environment(allocator, &.{}, .scratchpad, inside);
    defer freeEnvironment(allocator, built);

    var expected: [256]u8 = undefined;
    try testing.expectEqualStrings(
        try std.fmt.bufPrint(&expected, "TMPDIR={s}", .{inside}),
        built[0],
    );
    var expected_note: [256]u8 = undefined;
    try testing.expectEqualStrings(
        try std.fmt.bufPrint(&expected_note, "CHOCK_SCRATCHPAD={s}", .{inside}),
        built[1],
    );
}

test "a build with no cap mechanism asks for no capped area, and says so rather than pretending" {
    // **The rule this keeps: a false OK is worse than an honest refusal.** An
    // ordinary user on macOS cannot mount a filesystem, so a caller that asked
    // for a capped area there would be refused by `expressibleOn` and the whole
    // tool call would die. Asking for none instead is the honest answer, and
    // `chock doctor` already carries the fact as its `disk cap tmpfs` row so a
    // person reads `unsupported` and not a limit that holds.
    //
    // Mutation check: drop the `expresses.scratch_area` line from `tempAreaFor`
    // and this fails on Darwin with `.capped`.
    if (!sandbox.expresses.scratch_area) {
        try testing.expectEqual(TempArea.scratchpad, tempAreaFor(.{}));
        // Even limits that would carry a cap on a build that has one.
        try testing.expectEqual(
            TempArea.scratchpad,
            tempAreaFor((sandbox.Sandbox.Limits{}).narrow(.{})),
        );
        // And `TMPDIR` then names the scratchpad, which is a real directory of
        // this session's, and never `tmp_sandbox_dir`, which nothing mounts.
        try testing.expectEqualStrings("/a/host/scratch", tempDirFor(.scratchpad, "/a/host/scratch"));
    } else {
        try testing.expectEqual(TempArea.capped, tempAreaFor(.{}));
        try testing.expectEqualStrings(tmp_sandbox_dir, tempDirFor(.capped, "/a/host/scratch"));
    }
}

test "TMPDIR names the capped area and CHOCK_SCRATCHPAD names the notes, and they are two paths" {
    // **The split, in one place.** A file written through `TMPDIR` is gone when
    // the call ends, because that area is a tmpfs mounted for one call; a file
    // written through `CHOCK_SCRATCHPAD` is still there for the next call and
    // for a parent reading a child's answer. Two lifetimes need two paths, and
    // a test that let them be one string would let a later reader collapse them
    // back and take the cap or the handoff away without noticing.
    try testing.expect(!std.mem.eql(u8, sandbox_dir, tmp_sandbox_dir));
    try testing.expect(!std.mem.startsWith(u8, tmp_sandbox_dir, sandbox_dir ++ "/"));
    try testing.expect(!std.mem.startsWith(u8, sandbox_dir, tmp_sandbox_dir ++ "/"));
    try testing.expect(std.mem.startsWith(u8, tmp_sandbox_dir, "/run/chock/"));

    // Neither is the task output directory, which is bound read only and needs
    // no cap at all because nothing the model runs can write a byte into it.
    try testing.expect(!std.mem.eql(u8, tmp_sandbox_dir, tasks.sandbox_dir));
    try testing.expect(!std.mem.startsWith(u8, tasks.sandbox_dir, tmp_sandbox_dir ++ "/"));
}

test "a call whose limits cannot carry a cap keeps TMPDIR on the scratchpad" {
    // **The rule this must not defeat.** A tmpfs page is charged to the cgroup
    // the memory ceiling bounds, so an area that is a large part of that
    // ceiling turns a full area into a bare `SIGKILL` instead of `ENOSPC`:
    // measured, see `lib/chock-sandbox/linux/namespace.zig`'s own `Scratch`.
    // `Limits.narrow` lets a caller lower the memory ceiling and leave the cap
    // alone, so the pairing is asked about per call.
    const allocator = testing.allocator;

    // Only on a build that has a cap at all: one that has none answers
    // `.scratchpad` for every limit, which is the test above this.
    if (sandbox.expresses.scratch_area) {
        try testing.expectEqual(TempArea.capped, tempAreaFor(.{}));
        // A memory ceiling narrowed and the cap left where it was.
        try testing.expectEqual(
            TempArea.scratchpad,
            tempAreaFor((sandbox.Sandbox.Limits{}).narrow(.{ .memory_bytes = 1 << 20 })),
        );
    }

    const built = try environment(allocator, &.{}, .scratchpad, sandbox_dir);
    defer freeEnvironment(allocator, built);
    try testing.expectEqual(@as(usize, 2), built.len);
    // Exactly where `TMPDIR` pointed before the two were split: a call under
    // these limits behaves as Chock did, rather than getting a cap that would
    // arrive as an out of memory kill.
    try testing.expectEqualStrings("TMPDIR=" ++ sandbox_dir, built[0]);
    try testing.expectEqualStrings("CHOCK_SCRATCHPAD=" ++ sandbox_dir, built[1]);
}

test "a TMPDIR the dev shell states is replaced and never left beside Chock's own" {
    // `src/run.zig`'s own `sandboxEnvironment` copies every dev shell
    // variable into `sandbox.Config.env`, which is how the bad `TMPDIR`
    // reached a tool call at all. Two entries of one name is undefined in
    // POSIX, so replacing it is the only answer that is not "whichever libc
    // reads first".
    const allocator = testing.allocator;

    const base = [_][]const u8{
        "GIT_OBJECT_DIRECTORY=/run/chock/git/objects",
        "TMPDIR=/tmp/nix-shell.qHnEsN",
        "KEEP=me",
        // A project that states this itself must not end up with two of them
        // either, and a hostile one could aim the agent's notes anywhere.
        "CHOCK_SCRATCHPAD=/tmp/somewhere-else",
    };
    const built = try environment(allocator, &base, .capped, sandbox_dir);
    defer freeEnvironment(allocator, built);

    try testing.expectEqual(@as(usize, 4), built.len);
    try testing.expectEqualStrings("GIT_OBJECT_DIRECTORY=/run/chock/git/objects", built[0]);
    try testing.expectEqualStrings("KEEP=me", built[1]);
    try testing.expectEqualStrings("TMPDIR=" ++ tmp_sandbox_dir, built[2]);
    try testing.expectEqualStrings("CHOCK_SCRATCHPAD=" ++ sandbox_dir, built[3]);

    for (variable_names) |name| {
        var seen: usize = 0;
        for (built) |entry| {
            const equals = std.mem.indexOfScalar(u8, entry, '=').?;
            if (std.mem.eql(u8, entry[0..equals], name)) seen += 1;
        }
        try testing.expectEqual(@as(usize, 1), seen);
    }
}

test "the scratchpad and the task directory are siblings, both inside Chock's own runtime prefix" {
    // The rule this whole split rests on: the scratchpad is agent writable by
    // definition, so a `tasks` directory inside it would be writable whatever
    // the intent. Sibling directories, different mounts, different rules.
    try testing.expect(std.mem.startsWith(u8, sandbox_dir, "/run/chock/"));
    try testing.expect(std.mem.startsWith(u8, tasks.sandbox_dir, "/run/chock/"));
    try testing.expect(!std.mem.startsWith(u8, tasks.sandbox_dir, sandbox_dir ++ "/"));
    try testing.expect(!std.mem.startsWith(u8, sandbox_dir, tasks.sandbox_dir ++ "/"));
    try testing.expect(!std.mem.eql(u8, sandbox_dir, tasks.sandbox_dir));

    // And neither is the toolchain cache or the knowledgebase, the two
    // writable surfaces that do persist.
    try testing.expect(!std.mem.startsWith(u8, sandbox_dir, cache.sandbox_dir ++ "/"));
    try testing.expect(!std.mem.eql(u8, sandbox_dir, "/run/chock/memory"));
}

test "a subagent sees its own scratchpad, the parent sees all, and siblings see nothing of each other" {
    // The third one is the one with teeth. Two subagents that share a
    // directory have a channel the session log does not record, and the log
    // is the truth about what happened.
    const first: Agent = .{ .child = "01CHILDA" };
    const second: Agent = .{ .child = "01CHILDB" };

    try testing.expect(mayRead(first, first));
    try testing.expect(!mayRead(first, second));
    try testing.expect(!mayRead(second, first));

    try testing.expect(mayRead(.main, first));
    try testing.expect(mayRead(.main, second));
    try testing.expect(mayRead(.main, .main));

    try testing.expect(!mayRead(first, .main));
}

test "a child identifier that is not a plain name never reaches a path" {
    // A child identifier will come from a spawn the model asked for. A value
    // that reached a path unchecked is a path traversal, and this one would
    // climb out of the session directory entirely.
    const allocator = testing.allocator;

    try testing.expectError(error.BadChildId, leafFor(allocator, .{ .child = "../../etc" }));
    try testing.expectError(error.BadChildId, leafFor(allocator, .{ .child = "a/b" }));
    try testing.expectError(error.BadChildId, leafFor(allocator, .{ .child = "" }));

    const child = try leafFor(allocator, .{ .child = "01CHILDA" });
    defer allocator.free(child);
    try testing.expectEqualStrings("agents/01CHILDA/scratch", child);

    // The main agent's own files sit in a subdirectory of their own, so a
    // child identifier can never collide with a file the main agent wrote.
    const main = try leafFor(allocator, .main);
    defer allocator.free(main);
    try testing.expectEqualStrings(scratch_leaf, main);
    try testing.expect(!std.mem.eql(u8, main, agents_leaf));
}

test "the layout holds the directory the environment names, and the two beside it" {
    // A `make` given a `TMPDIR` that does not exist fails the same way as one
    // given the dev shell's, which is the fault this file exists to end.
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const session_dir = try std.fmt.allocPrint(allocator, "{s}/chock/01SESSION", .{path_buffer[0..path_len]});
    defer allocator.free(session_dir);

    try testing.expect(!exists(testing.io, session_dir));
    try makeLayout(testing.io, session_dir, null);
    try testing.expect(exists(testing.io, session_dir));

    inline for (.{ scratch_leaf, tasks_leaf, agents_leaf }) |leaf| {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ session_dir, leaf });
        defer allocator.free(path);
        try testing.expect(exists(testing.io, path));
    }

    // Called a second time on a directory that already exists, because a
    // session that resumes calls it exactly that way.
    try makeLayout(testing.io, session_dir, null);
    try testing.expect(exists(testing.io, session_dir));
}

test "a scratchpad over the bound is emptied, one under it is kept, and the task records survive both" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const session_dir = try std.fmt.allocPrint(allocator, "{s}/chock/01SESSION", .{path_buffer[0..path_len]});
    defer allocator.free(session_dir);
    try makeLayout(testing.io, session_dir, null);

    // The bound with an action behind it. A number nothing acts on is only a
    // number in a document.
    try testing.expectEqual(Verdict.keep, verdictFor(.{}));
    try testing.expectEqual(Verdict.keep, verdictFor(.{ .bytes = max_bytes, .files = 1 }));
    try testing.expectEqual(Verdict.empty, verdictFor(.{ .bytes = max_bytes + 1, .files = 2 }));

    const scratch_file = try std.fmt.allocPrint(allocator, "{s}/{s}/deep/notes.txt", .{ session_dir, scratch_leaf });
    defer allocator.free(scratch_file);
    try makeLayout(testing.io, std.fs.path.dirname(scratch_file).?, null);
    try writeBytes(scratch_file, "s" ** 300);

    const task_file = try std.fmt.allocPrint(allocator, "{s}/{s}/01.out", .{ session_dir, tasks_leaf });
    defer allocator.free(task_file);
    try writeBytes(task_file, "t" ** 90);

    const measured = measureScratch(allocator, testing.io, session_dir, max_bytes);
    try testing.expectEqual(@as(u64, 300), measured.bytes);
    try testing.expectEqual(@as(usize, 1), measured.files);

    const went = try clearScratch(allocator, testing.io, session_dir, null);
    try testing.expectEqual(@as(u64, 300), went.bytes);

    try testing.expectEqual(@as(u64, 0), measureScratch(allocator, testing.io, session_dir, max_bytes).bytes);
    const scratch_dir_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ session_dir, scratch_leaf });
    defer allocator.free(scratch_dir_path);
    try testing.expect(exists(testing.io, scratch_dir_path));
    try testing.expect(!exists(testing.io, std.fs.path.dirname(scratch_file).?));
    try testing.expect(fileSize(task_file) == 90);
}

test "removing the scratchpad takes the whole session directory, records and all" {
    // "Gone when the run ends" is a promise this function keeps. A temp
    // directory emptied by the machine at some point of its own choosing is
    // not the same promise.
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const session_dir = try std.fmt.allocPrint(allocator, "{s}/chock/01SESSION", .{path_buffer[0..path_len]});
    defer allocator.free(session_dir);
    try makeLayout(testing.io, session_dir, null);

    const task_file = try std.fmt.allocPrint(allocator, "{s}/{s}/01.out", .{ session_dir, tasks_leaf });
    defer allocator.free(task_file);
    try writeBytes(task_file, "kept while the session runs");

    remove(testing.io, session_dir);
    try testing.expect(!exists(testing.io, session_dir));

    // And a second call on a directory that is already gone is not a fault:
    // a session that failed early removes a scratchpad it never made.
    remove(testing.io, session_dir);
}

fn writeBytes(path: []const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{});
    defer file.close(testing.io);
    try file.writeStreamingAll(testing.io, contents);
}

fn fileSize(path: []const u8) u64 {
    const stat = std.Io.Dir.cwd().statFile(testing.io, path, .{}) catch return 0;
    return stat.size;
}

test "the directory a failed layout could not make reaches the caller" {
    // The point of the whole change. `error.ScratchpadDirectoryUnwritable`
    // says a layout failed. Only the diagnostic says which path, which is
    // what `chock run` prints for a person to act on.
    const under_a_file = "/dev/null/chock-scratchpad";
    var diag: ?Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(testing.allocator);

    try testing.expectError(
        error.ScratchpadDirectoryUnwritable,
        makeLayout(testing.io, under_a_file, sinkOf(testing.allocator, &diag)),
    );
    try testing.expectEqualStrings(
        under_a_file,
        diag.?.scratchpad_directory_not_made.path,
    );

    var buffer: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{diag.?});
    try testing.expect(std.mem.startsWith(u8, line, "making the scratchpad directory "));

    // A caller that wants none gets the same error and stores nothing.
    try testing.expectError(
        error.ScratchpadDirectoryUnwritable,
        makeLayout(testing.io, under_a_file, null),
    );
}

test "the directory named is one this file built, and it is read after that frame ended" {
    // The fault the `Sink` ended. The top level directory is the caller's own
    // slice, and it never dangled. **The three below it are built in a
    // `[std.fs.max_path_bytes]u8` buffer of `makeLayout`'s own frame**, and
    // the message used to point at that buffer. `dirtyTheFrame` writes over
    // it, which is what a printer does by accident.
    //
    // The debug allocator underneath is what makes this a test and not a
    // hope, and it also fails on a message nobody released.
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &path_buffer);

    // An ordinary file where the scratchpad belongs. The top level is then
    // made without a fault, because a name that is already there is not one
    // this has to make, and the first directory inside it cannot be made.
    const blocker = try std.fmt.allocPrint(gpa, "{s}/scratchpad", .{path_buffer[0..len]});
    defer gpa.free(blocker);
    {
        var handle = try std.Io.Dir.createFileAbsolute(testing.io, blocker, .{});
        handle.close(testing.io);
    }

    var diag: ?Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);

    try testing.expectError(
        error.ScratchpadDirectoryUnwritable,
        makeLayout(testing.io, blocker, sinkOf(gpa, &diag)),
    );
    std.mem.doNotOptimizeAway(dirtyTheFrame());

    var line_buffer: [std.fs.max_path_bytes + 256]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buffer, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, line, blocker) != null);
    try testing.expect(std.mem.endsWith(u8, diag.?.scratchpad_directory_not_made.path, "/" ++ scratch_leaf));
}

/// Write known bytes over the frame `makeLayout` used. A printer does this by
/// accident, which is why a borrowed path printed a row of whatever byte the
/// last call left.
fn dirtyTheFrame() u64 {
    var scratch: [2 * std.fs.max_path_bytes]u8 = undefined;
    @memset(&scratch, 0xAA);
    var sum: u64 = 0;
    for (scratch) |byte| sum +%= byte;
    return sum;
}
