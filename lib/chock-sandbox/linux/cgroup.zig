//! The cgroup v2 half of the resource limits. **The sandbox layers beside
//! this one are all about reach: what a tool call can open, mount, signal or
//! connect to. None of them bounds how much of the machine a tool call
//! consumes.** A model that writes a fork bomb, or that allocates until the
//! box swaps, passes every one of them.
//!
//! This file bounds two of those: **resident memory and the number of
//! processes.** `rlimits.zig` beside it bounds the rest and repeats these two
//! as a floor. Read that file's own top comment for which mechanism carries
//! which resource, and why the answer is both and not one.
//!
//! ## Why a cgroup and not only an rlimit
//!
//! Two rlimits are the wrong shape for these two resources, and a cgroup is
//! the right shape for both:
//!
//! * **`RLIMIT_AS` counts virtual address space, not resident memory.** A
//!   runtime that reserves a large region and never touches it is refused for
//!   memory it would never have used. `memory.max` counts pages that are
//!   really there.
//! * **`RLIMIT_NPROC` counts per user, not per sandbox.** See `rlimits.zig`'s
//!   own comment on `processes` for what was measured about that, which is
//!   less bad than it sounds on a recent kernel and still not a per sandbox
//!   bound. `pids.max` is a per cgroup count by construction, on every kernel
//!   that has cgroup v2.
//!
//! ## Why this is best effort, and never a reason to refuse to run
//!
//! A cgroup needs a writable cgroup v2 tree, which needs a unified hierarchy
//! and a delegated subtree. cgroup v1, a hybrid hierarchy, a container with
//! no cgroup mount of its own, and an init system that delegates nothing are
//! all real and all different from each other. So this file answers with a
//! `Support` value that names which of those happened, and the caller applies
//! the rlimit floor either way. **A machine with no cgroups still gets the
//! floor, and it is told plainly what it did not get.** See `Support`.
//!
//! ## The parent, and the rule that decides which one
//!
//! A limit file only exists in a cgroup whose **parent** lists that
//! controller in `cgroup.subtree_control`. So this file walks up from the
//! cgroup the calling process is in, and creates its own directory under the
//! first ancestor that already lists every controller it needs. Measured on
//! 2026-08-22: on a systemd machine that ancestor is
//! `user.slice/user-1000.slice/user@1000.service`, which lists
//! `cpu memory pids`, and a directory made there by an ordinary user has
//! `memory.max` and `pids.max` in it at once.
//!
//! **This file never writes `cgroup.subtree_control`, and that is a
//! decision.** The kernel refuses that write with `EBUSY` on a cgroup that
//! holds processes, which is the "no internal processes" rule. The only
//! cgroup this process could enable a controller on is the one it is already
//! in, and that cgroup holds the user's own login session. Making room there
//! means moving a person's shell into a leaf directory, and a sandbox must
//! not rearrange the machine it runs on to protect one tool call. So when no
//! ancestor delegates anything, the honest answer is
//! `Support.unavailable(.no_delegated_parent)` and the rlimit floor.
//!
//! ## Reading the base path once
//!
//! `/proc/self/cgroup` changes under the caller the moment the caller moves
//! into another cgroup, which is exactly what `Cgroup.join` does. So `create`
//! resolves the base path one time, before anything moves, and every later
//! step uses the paths it already holds.
//!
//! ## What a person reads when a limit ends a call
//!
//! A program killed by `memory.max` dies from `SIGKILL`, which reads exactly
//! like a timeout and exactly like a cancel. That is the confusing failure
//! this project keeps paying for. So `Cgroup.readEvents` reads the kernel's
//! own counters, `memory.events` and `pids.events`, after the wait, and the
//! driver turns them into a sentence that names the limit and its value. See
//! `Events`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// Where a cgroup v2 tree is mounted, in the order this file looks. The first
/// is the ordinary unified mount. The second is where a hybrid systemd puts
/// the v2 tree beside the v1 controllers, and it is worth one more `open`
/// because a hybrid machine can still give a real `pids.max`.
const mount_points = [_][:0]const u8{ "/sys/fs/cgroup", "/sys/fs/cgroup/unified" };

/// The controllers this file needs in an ancestor's `cgroup.subtree_control`
/// before a directory under it is worth making. Both, not either: a cgroup
/// that bounds processes and not memory is half an answer, and the caller
/// would then have to carry two different partial states instead of one.
const wanted_controllers = [_][]const u8{ "memory", "pids" };

/// The largest `/proc/self/cgroup` or `cgroup.subtree_control` this file
/// reads. Both are small kernel files; a read that needs more than this is
/// not a file this code understands.
const max_control_file_bytes = 4096;

/// Whether the cgroup layer applied, and when it did not, which of the very
/// different reasons it was.
///
/// **`unsupported` and `unavailable` are not the same fact.** `unsupported`
/// says this machine cannot do it at all, so a person reading it knows there
/// is nothing to configure. `unavailable` says the machine could and this
/// process was not permitted, which is a thing an administrator can change.
/// The shape is the one `lib/chock-core/lsp.zig` already uses for a language
/// server that is not there.
pub const Support = union(enum) {
    /// The cgroup was made and every limit asked for was written into it.
    ok,
    /// The caller asked for no limit a cgroup could carry, so none was made.
    /// **Not the same as a machine that cannot make one**, and a report that
    /// spelled the two the same way would have a person looking for a kernel
    /// fault that is not there.
    off,
    /// This machine has no cgroup v2 tree this code can use.
    unsupported: Reason,
    /// The machine has one and this process may not use it.
    unavailable: Reason,

    pub const Reason = enum {
        /// No `cgroup.controllers` file under any path in `mount_points`,
        /// and no `0::` line either. A cgroup v1 only machine.
        no_cgroup2_tree,
        /// The kernel put this process in a cgroup v2 hierarchy and no tree
        /// is mounted where this process can see one. **A different fact from
        /// `no_cgroup2_tree`**: the machine has the hierarchy and this mount
        /// namespace hides it, so a person reading it looks at the container
        /// and not at the kernel.
        no_cgroup2_mount,
        /// `/proc/self/cgroup` has no `0::` line, so this process is not in a
        /// unified hierarchy even though one is mounted somewhere. **A file
        /// that could not be read at all answers this too**, because both
        /// facts mean the same thing to a caller: no unified path was read.
        not_in_unified_hierarchy,
        /// The mount point joined to the `0::` path is longer than a path this
        /// code may hold. **Not a read that failed**: the file was read and
        /// the path it names does not fit. A truncated cgroup path names a
        /// different cgroup, so the join is refused instead.
        cgroup_path_too_long,
        /// No ancestor of this process's own cgroup lists every controller in
        /// `wanted_controllers` in its `cgroup.subtree_control`. See this
        /// file's own top comment for why nothing tries to enable one.
        no_delegated_parent,
        /// An ancestor delegates the controllers and `mkdirat` was refused
        /// under every one of them.
        create_refused,
        /// The directory was made and a limit file could not be written.
        write_refused,

        /// What happened, as a phrase that reads after "chock: ".
        pub fn text(self: Reason) []const u8 {
            return switch (self) {
                .no_cgroup2_tree => "this machine has no cgroup v2 tree",
                .no_cgroup2_mount => "no cgroup v2 tree is mounted where this process can see one",
                .not_in_unified_hierarchy => "this process is not in a cgroup v2 hierarchy",
                .cgroup_path_too_long => "this process's own cgroup path is too long to use",
                .no_delegated_parent => "no cgroup above this one delegates the memory and pids controllers",
                .create_refused => "a cgroup directory could not be made",
                .write_refused => "a cgroup limit file could not be written",
            };
        }
    };

    /// True when the limits really went on. The caller applies the rlimit
    /// floor whatever this answers; this only decides what the caller says
    /// about the layer, and whether there is a cgroup to read counters from
    /// and to remove afterwards.
    pub fn applied(self: Support) bool {
        return self == .ok;
    }

    pub fn format(self: Support, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ok => try writer.writeAll("the cgroup limits are on"),
            .off => try writer.writeAll("no cgroup limits were asked for"),
            .unsupported => |reason| try writer.print("no cgroup limits: {s}", .{reason.text()}),
            .unavailable => |reason| try writer.print("no cgroup limits: {s}", .{reason.text()}),
        }
    }
};

/// Which machine a `Support` answer is about.
///
/// **`/proc/self/cgroup` is relative to the reader's own cgroup namespace, so
/// the walk in `create` can answer about a cgroup that does not hold the
/// caller.** A process in a cgroup namespace reads `0::/` for a cgroup that is
/// deep in the machine's tree. `create` then joins that `/` to the mounted
/// root, walks a tree it is not in, and is refused. The refusal is true of
/// this process and false of the machine outside it. A report that says "this
/// machine" for such an answer sends a person to debug a kernel that works,
/// which is the fault this type exists to stop. Measured on 2026-08-24: from
/// inside `unshare --user --cgroup` on a systemd box whose user slice
/// delegates `memory` and `pids`, `create` answers `create_refused`.
///
/// **The test is membership, and not the shape of the path.** A container that
/// mounts a cgroup v2 tree of its own has the same `0::/` line and a coherent
/// view, and its answer is the truth about the only machine its processes will
/// ever run on. So this reads `cgroup.procs` at the path that was derived and
/// asks whether this process is really in it.
pub const Vantage = enum {
    /// The derived path names a cgroup that holds this process. The answer is
    /// about the machine that will run tool calls.
    own,
    /// A tree is mounted, and the derived path does not hold this process. A
    /// cgroup namespace does this. The answer is about this view only.
    foreign,
    /// The kernel has a cgroup v2 hierarchy for this process, and no tree is
    /// mounted where this process can see one. The answer is about this view
    /// only.
    not_mounted,
    /// This process is in no cgroup v2 hierarchy. There is no view to be
    /// wrong about, and the answer is about the machine.
    none,
    /// The membership could not be read, so which machine the answer is about
    /// was not measured. **Never reported as `own`**: an unproven vantage
    /// stated as this machine's is the fault itself.
    unknown,
};

/// Read the vantage. **Changes nothing**: it opens two kernel files and reads
/// them. `create` is the call that makes a directory.
pub fn readVantage() Vantage {
    var relative_buffer: [max_control_file_bytes]u8 = undefined;

    const root = findRoot() orelse {
        return if (readSelfCgroup(&relative_buffer) == null) .none else .not_mounted;
    };
    const relative = readSelfCgroup(&relative_buffer) orelse return .none;

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = joinPath(&path_buffer, root, relative) orelse return .unknown;

    const holds = holdsSelf(path_buffer[0..path_len]) orelse return .unknown;
    return if (holds) .own else .foreign;
}

/// Whether `dir`'s own `cgroup.procs` names this process. Null when the file
/// could not be read at all, which is "cannot tell" and never "no".
///
/// **Read in chunks, and not into one buffer.** The root cgroup of a running
/// machine lists every kernel thread, which is more than a control file buffer
/// holds, and a truncated read would answer "no" for a process whose number
/// comes after the cut. That answer would name a working machine a namespace.
fn holdsSelf(dir: []const u8) ?bool {
    var number: [32]u8 = undefined;
    const wanted = std.fmt.bufPrint(&number, "{d}", .{linux.getpid()}) catch return null;

    var full: [std.fs.max_path_bytes]u8 = undefined;
    const full_len = joinPath(&full, dir, "cgroup.procs") orelse return null;
    var full_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&full_z, full[0..full_len]) orelse return null;

    const fd_rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    // One line of `cgroup.procs` is one number. A line longer than this buffer
    // is no pid this process could have, so it is dropped rather than matched
    // on its first bytes.
    var line: [32]u8 = undefined;
    var line_len: usize = 0;
    var line_too_long = false;

    var buffer: [4096]u8 = undefined;
    while (true) {
        const rc = linux.read(fd, buffer[0..].ptr, buffer.len);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return null;
        if (rc == 0) break;

        for (buffer[0..rc]) |byte| {
            if (byte != '\n') {
                if (line_len == line.len) {
                    line_too_long = true;
                } else {
                    line[line_len] = byte;
                    line_len += 1;
                }
                continue;
            }
            if (!line_too_long and std.mem.eql(u8, line[0..line_len], wanted)) return true;
            line_len = 0;
            line_too_long = false;
        }
    }

    // The kernel ends every line of this file with a newline. This is for a
    // file that does not, so a last number is still read.
    if (line_too_long or line_len == 0) return false;
    return std.mem.eql(u8, line[0..line_len], wanted);
}

/// What the kernel's own counters say happened inside the cgroup. Read after
/// the sandboxed program has been waited for, and before the cgroup is
/// removed.
///
/// **These are the numbers that make a `SIGKILL` legible.** Without them a
/// program killed by `memory.max` is indistinguishable from one the harness
/// cancelled on its deadline, and this project has already paid for that
/// class of failure more than once.
pub const Events = struct {
    /// `memory.events`' own `oom_kill` field: how many processes the kernel
    /// killed in this cgroup for going over `memory.max`.
    oom_kills: u64 = 0,
    /// `pids.events`' own `max` field: how many times a fork in this cgroup
    /// was refused because `pids.max` was already reached.
    fork_refusals: u64 = 0,
};

/// One cgroup, made for one `spawn` call and removed when that call is over.
pub const Cgroup = struct {
    /// Whether the limits went on, and why not when they did not.
    support: Support,
    /// The absolute path of the directory this made, when it made one. Empty
    /// otherwise. Held as bytes rather than reopened by name later, so the
    /// path is resolved exactly once: see this file's own top comment.
    path_buffer: [std.fs.max_path_bytes]u8 = undefined,
    path_len: usize = 0,
    /// A write only descriptor on `cgroup.procs`, for `join`. Opened here, in
    /// the parent, because the process that has to move into the cgroup is a
    /// child that has already given up its ability to open a path: see
    /// `join`. -1 when there is no cgroup.
    procs_fd: i32 = -1,

    pub fn path(self: *const Cgroup) []const u8 {
        return self.path_buffer[0..self.path_len];
    }

    /// Make a cgroup for one `spawn` call and write `memory_bytes` and
    /// `processes` into it. Either may be null, meaning that resource is not
    /// bounded by a cgroup at all; a call with both null makes no cgroup and
    /// answers `unsupported(.no_cgroup2_tree)` only if there was none to
    /// begin with.
    ///
    /// **Allocates nothing.** `spawn` calls this from a process that is about
    /// to `fork`, and `lib/chock-core/tools.zig` calls `spawn` itself from a
    /// second thread. A lock taken here is a lock the child could inherit as
    /// held for ever. Every path in this file is built in a stack buffer and
    /// every read goes straight to the kernel.
    ///
    /// `name_seed` distinguishes two cgroups made by the same process at the
    /// same time. `spawn` passes a counter it increments atomically.
    pub fn create(memory_bytes: ?u64, processes: ?u64, name_seed: u64) Cgroup {
        // A cgroup with no limit in it is a directory to make, move a process
        // into, and remove again, for nothing. The caller decides; this only
        // refuses to do the work.
        std.debug.assert(memory_bytes != null or processes != null);

        var self = Cgroup{ .support = .{ .unsupported = .no_cgroup2_tree } };

        const root = findRoot() orelse {
            // A mount namespace can hide a tree the kernel really has, and
            // "this machine has no cgroup v2 tree" would then send a person
            // to a kernel that works. The `0::` line comes from the kernel
            // and not from the mount table, so it still answers when nothing
            // is mounted here. Measured on 2026-08-24.
            var hierarchy_buffer: [max_control_file_bytes]u8 = undefined;
            if (readSelfCgroup(&hierarchy_buffer) != null) {
                self.support = .{ .unavailable = .no_cgroup2_mount };
            }
            return self;
        };

        var self_path_buffer: [max_control_file_bytes]u8 = undefined;
        const relative = readSelfCgroup(&self_path_buffer) orelse {
            self.support = .{ .unsupported = .not_in_unified_hierarchy };
            return self;
        };

        // Walk up from this process's own cgroup. The first ancestor that
        // delegates every wanted controller is the parent a new directory is
        // worth making under, because only a child of such a cgroup has the
        // limit files at all. See this file's own top comment.
        var parent_buffer: [std.fs.max_path_bytes]u8 = undefined;
        var parent_len = joinPath(&parent_buffer, root, relative) orelse {
            self.support = .{ .unsupported = .cgroup_path_too_long };
            return self;
        };

        var found_a_delegating_parent = false;
        while (true) {
            if (delegatesWantedControllers(parent_buffer[0..parent_len])) {
                found_a_delegating_parent = true;
                if (self.makeUnder(parent_buffer[0..parent_len], name_seed)) {
                    self.applyLimits(memory_bytes, processes);
                    return self;
                }
            }
            parent_len = parentOf(parent_buffer[0..parent_len], root.len) orelse break;
        }

        self.support = if (found_a_delegating_parent)
            .{ .unavailable = .create_refused }
        else
            .{ .unavailable = .no_delegated_parent };
        return self;
    }

    /// Move the calling process, and therefore every process it goes on to
    /// make, into this cgroup.
    ///
    /// **Called by the first child, as its very first act, and through a
    /// descriptor rather than a path.** By the time the sandbox is built the
    /// child has pivoted into a root with no `/sys/fs/cgroup` in it, so a
    /// path would not resolve; and `closeInheritedFds` closes every
    /// descriptor before that, so this has to run before it. Writing `"0"`
    /// asks the kernel to move the writer itself, which is the only pid this
    /// child can name that means the same thing on both sides of the pid
    /// namespace it is about to make.
    ///
    /// Returns the errno when the kernel refused, so the caller can report
    /// which step failed rather than run on unbounded in silence.
    pub fn join(self: *const Cgroup) ?linux.E {
        if (self.procs_fd < 0) return null;
        const rc = linux.write(self.procs_fd, "0", 1);
        const write_errno = linux.errno(rc);
        if (write_errno != .SUCCESS) return write_errno;
        return null;
    }

    /// Close this process's copy of the `cgroup.procs` descriptor. The child
    /// closes it right after `join`, so `closeInheritedFds` never has to know
    /// about it; the parent closes it in `destroy`.
    pub fn closeProcsFd(self: *Cgroup) void {
        if (self.procs_fd >= 0) _ = linux.close(self.procs_fd);
        self.procs_fd = -1;
    }

    /// What the kernel counted while the sandboxed program ran. Zero
    /// everywhere when no cgroup was made, which reads the same as "no limit
    /// was hit" and is the right answer for a caller: there was no cgroup
    /// limit to hit.
    pub fn readEvents(self: *const Cgroup) Events {
        if (!self.support.applied()) return .{};
        return .{
            .oom_kills = self.readEventField("memory.events", "oom_kill "),
            .fork_refusals = self.readEventField("pids.events", "max "),
        };
    }

    /// Kill anything still in this cgroup, then remove it.
    ///
    /// **A cgroup with a process still in it refuses `rmdir` with `EBUSY`.**
    /// `spawn` calls this after it has waited for the process it forked, so
    /// the ordinary case is already empty, but a grandchild the kernel has
    /// not finished reaping is a real race and it is the one that leaves a
    /// directory behind for somebody to find months later. `cgroup.kill` is
    /// the reliable half: one write sends `SIGKILL` to every process in the
    /// cgroup and its descendants. The bounded retry below is the other half,
    /// for the moment between a kill and the last exit being accounted.
    ///
    /// Best effort throughout. A leaked cgroup is a nuisance and the caller
    /// already has whatever real outcome the call had; `create` sweeps stale
    /// siblings on a later call anyway.
    pub fn destroy(self: *Cgroup) void {
        self.closeProcsFd();
        if (!self.support.applied()) return;

        var path_z: [std.fs.max_path_bytes]u8 = undefined;
        const zeroed = nullTerminate(&path_z, self.path()) orelse return;

        const dir_rc = linux.open(zeroed, .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .CLOEXEC = true,
        }, 0);
        if (linux.errno(dir_rc) == .SUCCESS) {
            const dir_fd: i32 = @intCast(dir_rc);
            killMembers(dir_fd);
            _ = linux.close(dir_fd);
        }

        removeWhenEmpty(linux.AT.FDCWD, zeroed);
    }

    /// Try to make this call's own directory under `parent`. False when the
    /// kernel refused, so `create` can try the next ancestor up.
    fn makeUnder(self: *Cgroup, parent: []const u8, name_seed: u64) bool {
        sweepStaleSiblings(parent);

        var name_buffer: [64]u8 = undefined;
        const name = std.fmt.bufPrint(
            &name_buffer,
            "{s}{d}.{d}",
            .{ name_prefix, linux.getpid(), name_seed },
        ) catch return false;

        var full: [std.fs.max_path_bytes]u8 = undefined;
        const full_len = joinPath(&full, parent, name) orelse return false;

        var full_z: [std.fs.max_path_bytes]u8 = undefined;
        const zeroed = nullTerminate(&full_z, full[0..full_len]) orelse return false;
        if (linux.errno(linux.mkdirat(linux.AT.FDCWD, zeroed, 0o755)) != .SUCCESS) return false;

        @memcpy(self.path_buffer[0..full_len], full[0..full_len]);
        self.path_len = full_len;
        return true;
    }

    /// Write the limits, and open the descriptor `join` needs. A refusal here
    /// leaves the directory in place for `destroy` to remove and reports
    /// `write_refused`, rather than pretending a half written cgroup is a
    /// limit.
    fn applyLimits(self: *Cgroup, memory_bytes: ?u64, processes: ?u64) void {
        var number: [32]u8 = undefined;

        if (memory_bytes) |bytes| {
            const text = std.fmt.bufPrint(&number, "{d}", .{bytes}) catch return self.failWrite();
            if (!writeFileAt(self.path(), "memory.max", text)) return self.failWrite();
            // Swap is memory too, and a cgroup that bounds resident pages and
            // lets the same program push a gigabyte into swap has not stopped
            // the machine getting slow, which is the fault a person actually
            // notices. Best effort on purpose: a machine with no swap
            // accounting has no `memory.swap.max`, and that machine has no
            // swap problem to solve either.
            _ = writeFileAt(self.path(), "memory.swap.max", "0");
        }

        if (processes) |count| {
            const text = std.fmt.bufPrint(&number, "{d}", .{count}) catch return self.failWrite();
            if (!writeFileAt(self.path(), "pids.max", text)) return self.failWrite();
        }

        var procs: [std.fs.max_path_bytes]u8 = undefined;
        const procs_len = joinPath(&procs, self.path(), "cgroup.procs") orelse return self.failWrite();
        var procs_z: [std.fs.max_path_bytes]u8 = undefined;
        const zeroed = nullTerminate(&procs_z, procs[0..procs_len]) orelse return self.failWrite();
        const fd_rc = linux.open(zeroed, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd_rc) != .SUCCESS) return self.failWrite();
        self.procs_fd = @intCast(fd_rc);

        self.support = .ok;
    }

    fn failWrite(self: *Cgroup) void {
        self.support = .{ .unavailable = .write_refused };
    }

    /// Read one `key value` line out of a flat keyed cgroup file. `key`
    /// carries its own trailing space, so `max ` never matches `max_usage`.
    fn readEventField(self: *const Cgroup, file: []const u8, key: []const u8) u64 {
        var buffer: [max_control_file_bytes]u8 = undefined;
        const contents = readFileAt(self.path(), file, &buffer) orelse return 0;
        var lines = std.mem.splitScalar(u8, contents, '\n');
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, key)) continue;
            return std.fmt.parseInt(u64, std.mem.trim(u8, line[key.len..], " \r"), 10) catch 0;
        }
        return 0;
    }
};

/// The name every cgroup this file makes starts with, and it carries the pid
/// that made it: `chock.<pid>.<seq>`. `sweepStaleSiblings` only ever removes
/// a directory with this prefix, so a cgroup somebody else made is never
/// touched, and it reads the pid back out to decide which ones are stale.
const name_prefix = "chock.";

/// Remove any cgroup this code made and did not get to remove, which is what
/// a crash between `create` and `destroy` leaves behind, **and kill whatever
/// is still running inside it.**
///
/// **A directory is not the whole leak.** The kernel refuses `rmdir` on a
/// cgroup that still holds a process, so a sweep that only unlinks fails for
/// ever on exactly the cgroups that most need sweeping. Measured on the
/// owner's own machine on 2026-08-24: four processes from an escape test were
/// still in write loops two days after the run that made them, in three
/// cgroups a sweep had passed over many times. A normal exit tears its own
/// children down, which is why only an abnormal end leaves this, which is the
/// case where the cleanup matters most.
///
/// **A cgroup whose maker is still running is never touched, and `EBUSY` is
/// not enough to decide that.** A cgroup that `create` has just made and
/// nothing has moved into yet is empty, so `rmdir` on it succeeds, and a
/// second `spawn` sweeping at that moment deletes the first one's cgroup out
/// from under it. That is not a theory: it happened the first time this code
/// ran against `lib/chock-core/tools.zig`, which calls `spawn` from a thread
/// of its own, and the first call's child then met `ENODEV` writing to a
/// `cgroup.procs` whose directory no longer existed.
///
/// So the pid in the name decides. A pid that still answers `kill(pid, 0)` is
/// a maker that may still be using its cgroup, and its cgroup is left alone.
/// A pid that answers `ESRCH` is gone, and nothing will ever remove its
/// cgroup but this. The conservative direction is a leaked cgroup, which the
/// next sweep cleans up, and never a live one removed.
///
/// ## What this may kill, and the four things that must all hold first
///
/// This code sends `SIGKILL` on a developer's own workstation. A mistake here
/// ends a person's editor or their build, so ownership is proven and never
/// assumed. A directory is killed in only when every one of these holds:
///
/// 1. `parent` delegates the wanted controllers, because `create` walked to
///    it. Nothing else calls this function.
/// 2. The entry is a directory, by `getdents64`'s own type field.
/// 3. `ownedCgroupPid` reads the name as exactly `chock.<pid>.<seq>`, all
///    digits and nothing else. **An unrecognised name is refused**, and that
///    includes a name with the right prefix and any other shape.
/// 4. That pid answers `ESRCH`, so the process that made it is gone.
///
/// Then the kill goes through the cgroup's **own** control files and never
/// through a pid this code read anywhere else. A directory with no
/// `cgroup.kill` and no `cgroup.procs` in it is not a cgroup, and nothing in
/// it is signalled.
///
/// **The kill reaches a whole subtree and `rmdir` only removes a leaf.** So a
/// stale cgroup that has a cgroup inside it keeps its directory after
/// everything in it is dead. `create` makes no cgroup inside a cgroup, so such
/// a directory is one somebody else made, and leaving it is the same
/// conservative direction as everything above.
fn sweepStaleSiblings(parent: []const u8) void {
    var parent_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&parent_z, parent) orelse return;
    const dir_rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) return;
    const dir_fd: i32 = @intCast(dir_rc);
    defer _ = linux.close(dir_fd);

    var buffer: [4096]u8 = undefined;
    while (true) {
        const nread = linux.getdents64(dir_fd, &buffer, buffer.len);
        if (linux.errno(nread) != .SUCCESS or nread == 0) return;

        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            const name_offset = offset + @offsetOf(linux.dirent64, "name");
            const name_ptr: [*:0]const u8 = @ptrCast(&buffer[name_offset]);
            const name = std.mem.sliceTo(name_ptr, 0);
            offset += entry.reclen;

            if (entry.type != linux.DT.DIR) continue;
            const maker = ownedCgroupPid(name) orelse continue;
            if (processExists(maker)) continue;

            // The kill comes first. `rmdir` on a cgroup that still holds a
            // process answers `EBUSY` for ever, and the processes inside a
            // leaked cgroup are the leak that costs the machine something.
            const child_rc = linux.openat(dir_fd, name_ptr, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            }, 0);
            if (linux.errno(child_rc) == .SUCCESS) {
                const child_fd: i32 = @intCast(child_rc);
                killMembers(child_fd);
                _ = linux.close(child_fd);
            }

            removeWhenEmpty(dir_fd, name_ptr);
        }
    }
}

/// The pid out of `chock.<pid>.<seq>`, or null when `name` is not exactly one
/// of the names `makeUnder` writes.
///
/// **The name is the only evidence of ownership this code has, so it is read
/// strictly and an unrecognised name is refused.** Both parts must be decimal
/// digits and nothing else, there must be exactly one separator between them,
/// and there must be nothing after the second part. A looser read that
/// accepted a prefix and stopped would let a directory somebody else named
/// `chock.1.anything` be killed in.
fn ownedCgroupPid(name: []const u8) ?linux.pid_t {
    if (!std.mem.startsWith(u8, name, name_prefix)) return null;
    const rest = name[name_prefix.len..];

    const dot = std.mem.indexOfScalar(u8, rest, '.') orelse return null;
    const pid_text = rest[0..dot];
    const seq_text = rest[dot + 1 ..];
    if (pid_text.len == 0 or seq_text.len == 0) return null;

    // `parseInt` accepts a leading sign and an underscore between digits, and
    // this is a name written by `bufPrint` with `{d}`. Anything else is a name
    // this file did not write.
    for (pid_text) |byte| if (!std.ascii.isDigit(byte)) return null;
    for (seq_text) |byte| if (!std.ascii.isDigit(byte)) return null;

    _ = std.fmt.parseInt(u64, seq_text, 10) catch return null;
    const pid = std.fmt.parseInt(linux.pid_t, pid_text, 10) catch return null;
    if (pid <= 0) return null;
    return pid;
}

/// True when `pid` is still there, or when the kernel would not say. Both
/// answers mean "leave it alone": see `sweepStaleSiblings` for why the safe
/// direction is a leak.
///
/// `kill(pid, 0)` sends no signal. It asks the kernel whether the pid exists
/// and whether this process could signal it. `EPERM` therefore also means the
/// process is there, owned by somebody else, and `ESRCH` is the one answer
/// that says it is gone.
fn processExists(pid: linux.pid_t) bool {
    // The raw call, because signal 0 is not a member of `std.posix.SIG` and
    // `linux.kill` takes that enum. Signal 0 is the whole point here: it is
    // the documented way to ask about a pid without sending anything.
    const rc = linux.syscall2(.kill, @bitCast(@as(isize, pid)), 0);
    return linux.errno(rc) != .SRCH;
}

/// How many times the fallback in `killMembers` reads `cgroup.procs` again
/// after it has signalled what the last read named. A bound and not a loop
/// until empty: a process that forks as fast as it is killed would hold this
/// function for ever, and this runs on the path that makes a sandbox.
const max_kill_rounds = 16;

/// `SIGKILL` to every process in the cgroup open at `dir_fd`, and to every
/// process in a cgroup below it.
///
/// **`cgroup.kill` is preferred for a reason beyond it being one write: there
/// is no pid in it, so it has no pid reuse race.** A pid is not a name. The
/// kernel hands a number back out after the process that held it is reaped,
/// and this codebase has already killed an unrelated build on the owner's
/// machine because a reaped pid had been reused between the read that named
/// it and the signal that was sent to it. `cgroup.kill` names a cgroup, the
/// kernel signals what is in it at that moment, and no number crosses the
/// boundary. The file arrived in kernel 5.14, so its presence is detected by
/// opening it and never assumed from a version number.
///
/// The fallback carries the race the kernel file does not have, and it is the
/// best a kernel without that file allows. It re-reads `cgroup.procs` after
/// every round, because a forking child adds members while this works, and a
/// single read then leaves the newest ones alive.
///
/// Best effort throughout: this is cleanup, and every caller has its real
/// outcome already.
fn killMembers(dir_fd: i32) void {
    const kill_rc = linux.openat(dir_fd, "cgroup.kill", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(kill_rc) == .SUCCESS) {
        const kill_fd: i32 = @intCast(kill_rc);
        defer _ = linux.close(kill_fd);
        while (true) {
            const rc = linux.write(kill_fd, "1", 1);
            const write_errno = linux.errno(rc);
            if (write_errno == .INTR) continue;
            // A refusal falls through to the fallback rather than returning.
            // The kernel that has this file is not the only thing that can
            // answer no to a write on it.
            if (write_errno == .SUCCESS) return;
            break;
        }
    }

    var round: usize = 0;
    while (round < max_kill_rounds) : (round += 1) {
        const signalled = signalMembers(dir_fd) orelse return;
        if (signalled == 0) return;
        _ = linux.syscall0(.sched_yield);
    }
}

/// `SIGKILL` to every pid named by this cgroup's own `cgroup.procs`, and how
/// many were signalled. Null when the file could not be read at all, which is
/// "this is not a cgroup this code may kill in" and never "it is empty".
///
/// **This process's own pid is skipped.** It cannot be in a stale sibling, and
/// a bug that put it there must leak a directory rather than kill the harness.
fn signalMembers(dir_fd: i32) ?usize {
    const fd_rc = linux.openat(dir_fd, "cgroup.procs", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const self_pid = linux.getpid();
    var signalled: usize = 0;

    // One line of this file is one number. A line longer than this buffer is
    // no pid, so it is dropped rather than read from its first bytes.
    var line: [32]u8 = undefined;
    var line_len: usize = 0;
    var line_too_long = false;

    var buffer: [4096]u8 = undefined;
    while (true) {
        const rc = linux.read(fd, buffer[0..].ptr, buffer.len);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return null;
        if (rc == 0) break;

        for (buffer[0..rc]) |byte| {
            if (byte != '\n') {
                if (line_len == line.len) {
                    line_too_long = true;
                } else {
                    line[line_len] = byte;
                    line_len += 1;
                }
                continue;
            }
            if (!line_too_long and line_len > 0) {
                if (signalOne(line[0..line_len], self_pid)) signalled += 1;
            }
            line_len = 0;
            line_too_long = false;
        }
    }

    // The kernel ends every line of this file with a newline. This is for a
    // file that does not, so a last number is still read.
    if (!line_too_long and line_len > 0) {
        if (signalOne(line[0..line_len], self_pid)) signalled += 1;
    }
    return signalled;
}

/// `SIGKILL` to one line of `cgroup.procs`. False when the line is not a pid
/// this may signal, which includes the caller's own.
fn signalOne(text: []const u8, self_pid: linux.pid_t) bool {
    for (text) |byte| if (!std.ascii.isDigit(byte)) return false;
    const pid = std.fmt.parseInt(linux.pid_t, text, 10) catch return false;
    if (pid <= 0 or pid == self_pid) return false;
    return linux.errno(linux.kill(pid, .KILL)) == .SUCCESS;
}

/// The pause between two attempts in `removeWhenEmpty`, and how many attempts
/// it makes. The product is the longest this waits for one directory.
///
/// **A killed process leaves its cgroup later than the kill returns, and the
/// wait is time and not work.** A write to `cgroup.kill` queues `SIGKILL` and
/// returns before any of the killed processes has run again, so `rmdir` right
/// after it answers `EBUSY` until the kernel has accounted the last exit. That
/// gap was measured on this project's 128 core development box, over 40 runs
/// of kill and remove: 80us at best, 504us at worst.
///
/// Until 2026-08-25 this loop had 64 attempts and a `sched_yield` between
/// them, on the reasoning that the exit is work another runnable task does.
/// **A machine with an idle CPU has nothing to yield to**, so the yield
/// returned at once, all 64 attempts ran inside about 200us, and the directory
/// was left behind on 16 of those 40 runs. This is why the pause is a sleep.
const remove_pause_ns = 500 * std.time.ns_per_us;
const remove_attempts = 400;

/// Remove a cgroup directory, once the kernel has finished accounting the
/// exits of what was in it.
fn removeWhenEmpty(dir_fd: i32, name: [*:0]const u8) void {
    var attempt: usize = 0;
    while (attempt < remove_attempts) : (attempt += 1) {
        // `unlinkat` with `AT.REMOVEDIR` rather than `rmdir`, which is not a
        // system call on every architecture this project builds for.
        const rc = linux.unlinkat(dir_fd, name, linux.AT.REMOVEDIR);
        switch (linux.errno(rc)) {
            // Gone, either by this call or by an earlier one: `destroy` is
            // called again by a `defer` in more than one caller, and a second
            // call must stop at once rather than spin out its whole retry
            // budget against a directory that is already removed.
            .SUCCESS, .NOENT => return,
            else => {},
        }
        // The first attempt runs before any pause, so a cgroup that is already
        // empty costs one system call and no wait at all.
        const request = linux.timespec{ .sec = 0, .nsec = remove_pause_ns };
        _ = linux.nanosleep(&request, null);
    }
}

/// The mount point of a cgroup v2 tree, or null when this machine has none.
fn findRoot() ?[:0]const u8 {
    for (&mount_points) |candidate| {
        var probe: [std.fs.max_path_bytes]u8 = undefined;
        const len = joinPath(&probe, candidate, "cgroup.controllers") orelse continue;
        var probe_z: [std.fs.max_path_bytes]u8 = undefined;
        const zeroed = nullTerminate(&probe_z, probe[0..len]) orelse continue;
        const fd_rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd_rc) != .SUCCESS) continue;
        _ = linux.close(@intCast(fd_rc));
        return candidate;
    }
    return null;
}

/// The cgroup v2 path of this process, relative to the tree's mount point:
/// the part after `0::` on the one line of `/proc/self/cgroup` that names
/// hierarchy 0. A machine with only cgroup v1 has no such line.
///
/// **Read exactly once, by `create`, before anything moves.** This file
/// changes under the caller the moment `join` runs, so a second read later
/// answers a different question than the first one did.
fn readSelfCgroup(buffer: []u8) ?[]const u8 {
    const contents = readWholeFile("/proc/self/cgroup", buffer) orelse return null;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "0::")) continue;
        const rest = std.mem.trim(u8, line[3..], " \r");
        if (rest.len == 0) return null;
        return rest;
    }
    return null;
}

/// True when `dir`'s own `cgroup.subtree_control` lists every controller in
/// `wanted_controllers`. That file is what decides whether a *child* of `dir`
/// has `memory.max` and `pids.max` in it at all.
fn delegatesWantedControllers(dir: []const u8) bool {
    var buffer: [max_control_file_bytes]u8 = undefined;
    const contents = readFileAt(dir, "cgroup.subtree_control", &buffer) orelse return false;
    for (&wanted_controllers) |wanted| {
        var found = false;
        var names = std.mem.tokenizeAny(u8, contents, " \n\r\t");
        while (names.next()) |name| {
            if (std.mem.eql(u8, name, wanted)) found = true;
        }
        if (!found) return false;
    }
    return true;
}

/// The length of `dir` with its last path component removed, or null once
/// `dir` is `root_len` long, which is the tree's own mount point and has no
/// parent this code may look above.
fn parentOf(dir: []const u8, root_len: usize) ?usize {
    if (dir.len <= root_len) return null;
    const slash = std.mem.lastIndexOfScalar(u8, dir, '/') orelse return null;
    if (slash < root_len) return root_len;
    return slash;
}

/// `a/b` in `buffer`, with exactly one separator between them and no
/// allocation. Null when the result does not fit.
fn joinPath(buffer: []u8, a: []const u8, b: []const u8) ?usize {
    const trimmed_a = if (a.len > 1 and a[a.len - 1] == '/') a[0 .. a.len - 1] else a;
    const trimmed_b = if (b.len > 0 and b[0] == '/') b[1..] else b;
    const needed = trimmed_a.len + 1 + trimmed_b.len;
    if (needed > buffer.len) return null;
    @memcpy(buffer[0..trimmed_a.len], trimmed_a);
    buffer[trimmed_a.len] = '/';
    @memcpy(buffer[trimmed_a.len + 1 ..][0..trimmed_b.len], trimmed_b);
    return needed;
}

/// A null terminated copy of `text` in `buffer`, for a syscall that takes a
/// path. Null when it does not fit, which every caller reports as a refusal
/// rather than truncating a path.
fn nullTerminate(buffer: []u8, text: []const u8) ?[:0]const u8 {
    if (text.len + 1 > buffer.len) return null;
    @memcpy(buffer[0..text.len], text);
    buffer[text.len] = 0;
    return buffer[0..text.len :0];
}

fn readFileAt(dir: []const u8, name: []const u8, buffer: []u8) ?[]const u8 {
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const len = joinPath(&full, dir, name) orelse return null;
    var full_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&full_z, full[0..len]) orelse return null;
    return readWholeFile(zeroed, buffer);
}

fn readWholeFile(path: [*:0]const u8, buffer: []u8) ?[]const u8 {
    const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(fd, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return null;
        if (rc == 0) break;
        filled += rc;
    }
    return buffer[0..filled];
}

/// Write `contents` to `dir/name`. A cgroup control file takes the whole
/// value in one write, so a short write is a refusal and never something to
/// continue from.
fn writeFileAt(dir: []const u8, name: []const u8, contents: []const u8) bool {
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const len = joinPath(&full, dir, name) orelse return false;
    var full_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&full_z, full[0..len]) orelse return false;

    const fd_rc = linux.open(zeroed, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const rc = linux.write(fd, contents.ptr, contents.len);
    return linux.errno(rc) == .SUCCESS and rc == contents.len;
}

test "joinPath puts exactly one separator between two parts" {
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings("/sys/fs/cgroup/pids.max", buffer[0..joinPath(&buffer, "/sys/fs/cgroup", "pids.max").?]);
    try std.testing.expectEqualStrings("/sys/fs/cgroup/pids.max", buffer[0..joinPath(&buffer, "/sys/fs/cgroup/", "pids.max").?]);
    try std.testing.expectEqualStrings("/sys/fs/cgroup/pids.max", buffer[0..joinPath(&buffer, "/sys/fs/cgroup", "/pids.max").?]);

    // A path that does not fit is refused rather than truncated: a truncated
    // cgroup path names a different cgroup, and this code writes limits into
    // whatever it names.
    var tiny: [4]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), joinPath(&tiny, "/sys/fs/cgroup", "pids.max"));
}

test "parentOf walks up and stops at the tree's own mount point" {
    const root = "/sys/fs/cgroup";
    const full = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/a.scope";

    var len = full.len;
    len = parentOf(full[0..len], root.len).?;
    try std.testing.expectEqualStrings("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service", full[0..len]);
    len = parentOf(full[0..len], root.len).?;
    try std.testing.expectEqualStrings("/sys/fs/cgroup/user.slice/user-1000.slice", full[0..len]);
    len = parentOf(full[0..len], root.len).?;
    try std.testing.expectEqualStrings("/sys/fs/cgroup/user.slice", full[0..len]);
    len = parentOf(full[0..len], root.len).?;
    try std.testing.expectEqualStrings(root, full[0..len]);

    // The mount point itself has no parent this code may look above. Walking
    // past it would read `/sys/fs`, which is not a cgroup at all.
    try std.testing.expectEqual(@as(?usize, null), parentOf(full[0..len], root.len));
}

test "readSelfCgroup takes the unified line and refuses a v1 only file" {
    var buffer: [max_control_file_bytes]u8 = undefined;

    // A hybrid file: v1 controllers first, then the one unified line.
    const hybrid = "8:memory:/user.slice\n4:pids:/user.slice\n0::/user.slice/user-1000.slice\n";
    @memcpy(buffer[0..hybrid.len], hybrid);
    var lines = std.mem.splitScalar(u8, buffer[0..hybrid.len], '\n');
    var found: ?[]const u8 = null;
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "0::")) found = std.mem.trim(u8, line[3..], " \r");
    }
    try std.testing.expectEqualStrings("/user.slice/user-1000.slice", found.?);

    // The real function against the real machine, which is allowed to answer
    // either way: a machine with no cgroup v2 is a supported machine, and
    // this test pins that the two answers are told apart rather than that
    // this particular box has one.
    //
    // Linux only past this line. Every call below reaches the kernel through
    // a raw Linux syscall number, and this file is compiled for Darwin only
    // because `Sandbox.zig` names its types. See
    // `rlimits.zig`'s own release test for what such a call did on Darwin.
    if (builtin.os.tag != .linux) return;
    var live: [max_control_file_bytes]u8 = undefined;
    if (readSelfCgroup(&live)) |relative| {
        try std.testing.expect(relative.len > 0);
        try std.testing.expectEqual(@as(u8, '/'), relative[0]);
    }
}

test "a Support value says which of the three things happened, in words" {
    var buffer: [128]u8 = undefined;

    try std.testing.expectEqualStrings(
        "the cgroup limits are on",
        try std.fmt.bufPrint(&buffer, "{f}", .{@as(Support, .ok)}),
    );
    try std.testing.expectEqualStrings(
        "no cgroup limits: this machine has no cgroup v2 tree",
        try std.fmt.bufPrint(&buffer, "{f}", .{Support{ .unsupported = .no_cgroup2_tree }}),
    );
    try std.testing.expectEqualStrings(
        "no cgroup limits: no cgroup above this one delegates the memory and pids controllers",
        try std.fmt.bufPrint(&buffer, "{f}", .{Support{ .unavailable = .no_delegated_parent }}),
    );
    // A tree this view cannot see is not a machine that has none. A reader who
    // gets the first sentence for the second fact looks at a kernel that
    // works.
    try std.testing.expectEqualStrings(
        "no cgroup limits: no cgroup v2 tree is mounted where this process can see one",
        try std.fmt.bufPrint(&buffer, "{f}", .{Support{ .unavailable = .no_cgroup2_mount }}),
    );

    // Only `ok` counts as applied. A caller that read `unavailable` as a
    // limit would report a bound that is not there, which is the one thing
    // this whole type exists to stop.
    try std.testing.expect(@as(Support, .ok).applied());
    try std.testing.expect(!(Support{ .unsupported = .no_cgroup2_tree }).applied());
    try std.testing.expect(!(Support{ .unavailable = .create_refused }).applied());

    // Every reason reads differently, so a person can tell which one they
    // got. Two reasons with one sentence would be a report that names
    // nothing.
    const reasons = std.enums.values(Support.Reason);
    for (reasons, 0..) |reason, i| {
        try std.testing.expect(reason.text().len > 0);
        for (reasons[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, reason.text(), other.text()));
        }
    }
}

test "the vantage tells this machine's own tree from a namespace's view of it" {
    // Linux only, for the reason the tests above state: every call here is a
    // raw Linux syscall.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const here = readVantage();
    // A machine in no cgroup v2 hierarchy has no view to be wrong about.
    if (here == .none) return error.SkipZigTest;

    // A cgroup that was really made proves the path this file derives is this
    // machine's own. **This is the other direction of the fault**: a vantage
    // stuck on `foreign` would put a container caveat on every report from a
    // machine that has no container, which is a false alarm in place of a
    // false negative. The directory is this call's own and is removed again.
    {
        var group = Cgroup.create(64 << 20, 16, 0xC06400);
        defer group.destroy();
        if (group.support == .ok) try std.testing.expectEqual(Vantage.own, here);
    }

    // A box that is already inside a container measures nothing below: its own
    // view is not this machine's either, so the two answers would be the same
    // and the test would pin nothing.
    if (here != .own) return error.SkipZigTest;

    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return error.SkipZigTest;
    }

    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        // A user namespace first, because an ordinary user may not make a
        // cgroup namespace without one. A fork carries only the calling
        // thread, so the child is single threaded and the kernel takes
        // `CLONE_NEWUSER` from it.
        const flags = linux.CLONE.NEWUSER | linux.CLONE.NEWCGROUP;
        const record: [2]u8 = if (linux.errno(linux.unshare(flags)) == .SUCCESS)
            .{ 1, @intCast(@intFromEnum(readVantage())) }
        else
            .{ 0, 0 };
        _ = linux.write(fds[1], &record, record.len);
        // Never a return: this is a forked child of a test binary, and none of
        // what that binary holds is this process's to unwind.
        std.process.exit(0);
    }

    _ = linux.close(fds[1]);
    var record: [2]u8 = .{ 0, 0 };
    var held: usize = 0;
    while (held < record.len) {
        const rc = linux.read(fds[0], record[held..].ptr, record.len - held);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        held += rc;
    }
    _ = linux.close(fds[0]);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);

    // A kernel that refuses this user a namespace measured nothing, and an
    // assertion on that would be a test of the box's own sysctl.
    if (held != record.len or record[0] != 1) return error.SkipZigTest;

    // The byte came over a pipe, so it is read with `fromInt` and never with
    // `@enumFromInt`.
    const inside = std.enums.fromInt(Vantage, record[1]) orelse return error.SkipZigTest;

    // **The fault this test is for.** Inside a cgroup namespace the kernel
    // writes `0::/` for a cgroup that is deep in this machine's tree, so a
    // reader that trusts that path walks the mounted root, which is a cgroup
    // that does not hold it, and `create` is refused there. Drop the
    // membership read in `holdsSelf` and this answers `own`, and `chock
    // doctor` goes back to reporting a working machine as blocked.
    try std.testing.expectEqual(Vantage.foreign, inside);
}

test "a cgroup is made, holds the limits asked for, and is removed again" {
    // Linux only, for the reason the test above states: every call in this
    // file is a raw Linux syscall, and this file compiles for Darwin only
    // because `Sandbox.zig` names its types.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // The real thing against the real machine. A machine with no cgroup v2
    // and no delegation is a machine this project supports, so the check
    // there is that `create` said so plainly and made nothing, not that it
    // succeeded.
    var group = Cgroup.create(64 << 20, 16, 0xC0FFEE);
    defer group.destroy();

    switch (group.support) {
        .off, .unsupported, .unavailable => {
            // Nothing was made, so nothing may be left behind, and there must
            // be no descriptor for a caller to write a pid into.
            try std.testing.expectEqual(@as(usize, 0), group.path_len);
            try std.testing.expectEqual(@as(i32, -1), group.procs_fd);
            return;
        },
        .ok => {},
    }

    // The limits are really in the files, read back from the kernel rather
    // than from the value this code just wrote. A `create` that made the
    // directory and wrote nothing would pass every check above this line.
    var buffer: [max_control_file_bytes]u8 = undefined;
    const memory_max = readFileAt(group.path(), "memory.max", &buffer).?;
    try std.testing.expectEqualStrings("67108864", std.mem.trim(u8, memory_max, " \n"));
    const pids_max = readFileAt(group.path(), "pids.max", &buffer).?;
    try std.testing.expectEqualStrings("16", std.mem.trim(u8, pids_max, " \n"));

    // And a descriptor a child can move itself through.
    try std.testing.expect(group.procs_fd >= 0);

    // Kept for the check after destroy below, because destroy clears it.
    var kept: [std.fs.max_path_bytes]u8 = undefined;
    const kept_path = kept[0..group.path_len];
    @memcpy(kept_path, group.path());

    group.destroy();

    // Really gone. A destroy that only closed the descriptor would leave a
    // cgroup per tool call on the machine for ever, which is the leak this
    // is here to stop.
    var after: [max_control_file_bytes]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), readFileAt(kept_path, "pids.max", &after));
}

test "a cgroup name is read strictly, and any other shape is refused" {
    // The name is the only evidence of ownership the sweep has, and the sweep
    // sends `SIGKILL`. Every line below is a directory somebody else could
    // make in the same parent.
    try std.testing.expectEqual(@as(?linux.pid_t, 1130789), ownedCgroupPid("chock.1130789.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, 7), ownedCgroupPid("chock.7.18446744073709551615"));

    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock."));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.1"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.1."));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock..1"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.0.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chocks.1.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("session.scope"));

    // A sign, an underscore and a trailing part are all things `parseInt`
    // accepts or a lazy read would stop before. `bufPrint` with `{d}` writes
    // none of them, so none of them is a name this file wrote.
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.+1.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.-1.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.1_0.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.1.0.mine"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.1.0x0"));

    // A number no pid can hold is refused rather than wrapped into one that
    // some live process is using.
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.99999999999999999999.0"));
}

/// The first ancestor of this process's own cgroup that delegates every wanted
/// controller, in `buffer`. The two tests below make a directory of their own
/// there, which is the same place `create` makes one.
fn testDelegatingAncestor(buffer: []u8) ?usize {
    const root = findRoot() orelse return null;
    var relative_buffer: [max_control_file_bytes]u8 = undefined;
    const relative = readSelfCgroup(&relative_buffer) orelse return null;

    var len = joinPath(buffer, root, relative) orelse return null;
    while (true) {
        if (delegatesWantedControllers(buffer[0..len])) return len;
        len = parentOf(buffer[0..len], root.len) orelse return null;
    }
}

fn testMakeDir(path: []const u8) bool {
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, path) orelse return false;
    return linux.errno(linux.mkdirat(linux.AT.FDCWD, zeroed, 0o755)) == .SUCCESS;
}

fn testRemoveDir(path: []const u8) void {
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, path) orelse return;
    _ = linux.unlinkat(linux.AT.FDCWD, zeroed, linux.AT.REMOVEDIR);
}

fn testOpenDir(path: []const u8) ?i32 {
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, path) orelse return null;
    const rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

/// A pid whose process this test made, waited for, and reaped. The tests below
/// name a cgroup with it, so the sweep reads its maker as gone.
///
/// **Not a number picked out of the air.** The kernel hands pids out in order
/// and only reuses one after it has wrapped at `/proc/sys/kernel/pid_max`, so
/// the pid of a process that has just exited is the number least likely to
/// belong to somebody else while this test runs.
fn testReapedPid() ?linux.pid_t {
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return null;
    // Never a return: this is a forked child of a test binary, and none of
    // what that binary holds is this process's to unwind.
    if (rc == 0) std.process.exit(0);

    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(pid, &status, 0);
    if (linux.errno(wait_rc) != .SUCCESS) return null;
    if (processExists(pid)) return null;
    return pid;
}

/// A child of this test that waits, and then leaves by itself.
///
/// **The bound is the safety net, and it is the point.** This file kills
/// processes on a developer's own workstation, and a test of it that leaves
/// one behind is the very fault this test is about. Ten seconds is far longer
/// than a sweep needs and short enough that a sweep which kills nothing still
/// leaks nothing that outlives the test run.
fn testSpawnSleeper() ?linux.pid_t {
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return null;
    if (rc == 0) {
        var left: usize = 0;
        while (left < 100) : (left += 1) {
            const request = linux.timespec{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
            _ = linux.nanosleep(&request, null);
        }
        std.process.exit(0);
    }
    return @intCast(rc);
}

fn testKillAndReap(pid: linux.pid_t) void {
    _ = linux.kill(pid, .KILL);
    var status: u32 = undefined;
    var rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(pid, &status, 0);
}

/// The status of a process this test made, after the code under test has
/// killed it. Blocks: the sleeper leaves by itself in the end, so a sweep that
/// killed nothing gives an exit status here instead of hanging the run.
fn testReap(pid: linux.pid_t) ?u32 {
    var status: u32 = undefined;
    var rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(pid, &status, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    return status;
}

/// Whether the kernel says `pid` is in the cgroup at `dir`. The tests below
/// assert this before they assert anything about a sweep, so a setup that
/// silently put the process nowhere cannot read as a kill.
fn testCgroupHolds(dir: []const u8, pid: linux.pid_t) bool {
    var number: [32]u8 = undefined;
    const wanted = std.fmt.bufPrint(&number, "{d}", .{pid}) catch return false;

    var buffer: [max_control_file_bytes]u8 = undefined;
    const contents = readFileAt(dir, "cgroup.procs", &buffer) orelse return false;
    var lines = std.mem.tokenizeAny(u8, contents, "\n");
    while (lines.next()) |line| {
        if (std.mem.eql(u8, std.mem.trim(u8, line, " \r"), wanted)) return true;
    }
    return false;
}

test "a sweep kills what a stale cgroup still holds, and then removes it" {
    // Linux only, for the reason the tests above state: every call here is a
    // raw Linux syscall.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // **Everything this test makes is inside one directory it made itself.**
    // The outer name carries this process's own live pid, so a sweep running
    // in another process leaves it alone, and this test sweeps only its own
    // directory. Nothing here writes `cgroup.subtree_control`, and no cgroup
    // this test did not make is opened for anything but reading.
    var ancestor: [std.fs.max_path_bytes]u8 = undefined;
    const ancestor_len = testDelegatingAncestor(&ancestor) orelse return error.SkipZigTest;

    var outer_name: [64]u8 = undefined;
    const mine = try std.fmt.bufPrint(&outer_name, "{s}{d}.{d}", .{ name_prefix, linux.getpid(), 0xC6041 });
    var outer_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const outer_len = joinPath(&outer_buffer, ancestor[0..ancestor_len], mine) orelse return error.SkipZigTest;
    const outer = outer_buffer[0..outer_len];
    if (!testMakeDir(outer)) return error.SkipZigTest;
    defer testRemoveDir(outer);

    // The cgroup the sweep must clean: named the way this file names one, and
    // carrying a maker that is gone.
    const dead_maker = testReapedPid() orelse return error.SkipZigTest;
    var stale_name: [64]u8 = undefined;
    const leaked = try std.fmt.bufPrint(&stale_name, "{s}{d}.{d}", .{ name_prefix, dead_maker, 0 });
    var stale_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const stale_len = joinPath(&stale_buffer, outer, leaked) orelse return error.SkipZigTest;
    const stale = stale_buffer[0..stale_len];
    if (!testMakeDir(stale)) return error.SkipZigTest;
    defer testRemoveDir(stale);

    const victim = testSpawnSleeper() orelse return error.SkipZigTest;
    var reaped = false;
    defer if (!reaped) testKillAndReap(victim);

    var number: [32]u8 = undefined;
    const victim_text = try std.fmt.bufPrint(&number, "{d}", .{victim});
    try std.testing.expect(writeFileAt(stale, "cgroup.procs", victim_text));

    // The setup is real before the sweep is asserted about. A process that
    // never went in would be killed by nothing and prove nothing.
    try std.testing.expect(testCgroupHolds(stale, victim));

    sweepStaleSiblings(outer);

    // **The fact this test exists for.** Nothing in this test signals the
    // victim before this line, and the victim leaves by itself only after ten
    // seconds and with a status of zero. So a status of "killed by SIGKILL"
    // here was the sweep's doing and nothing else's. A sweep that only called
    // `unlinkat`, which is what this file did until 2026-08-24, reaches this
    // line with a process that is still running.
    const status = testReap(victim) orelse return error.SkipZigTest;
    reaped = true;
    try std.testing.expect(linux.W.IFSIGNALED(status));
    try std.testing.expectEqual(linux.SIG.KILL, linux.W.TERMSIG(status));

    // And the directory is gone, which is the half that was already there.
    // The kernel refuses `rmdir` on a cgroup that still holds a process, so
    // this line only passes because the lines above it did.
    var after: [max_control_file_bytes]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), readFileAt(stale, "cgroup.procs", &after));
}

test "the fallback signals every pid the cgroup lists, and nothing else" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // `cgroup.kill` is what a kernel from 5.14 on uses, so this box never
    // reaches the fallback through `killMembers`. The fallback is called
    // directly here, because a kernel older than that is a machine this
    // project still supports and an untested path on it is a leak nobody
    // would see until it was on somebody's workstation.
    var ancestor: [std.fs.max_path_bytes]u8 = undefined;
    const ancestor_len = testDelegatingAncestor(&ancestor) orelse return error.SkipZigTest;

    var outer_name: [64]u8 = undefined;
    const mine = try std.fmt.bufPrint(&outer_name, "{s}{d}.{d}", .{ name_prefix, linux.getpid(), 0xC6042 });
    var outer_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const outer_len = joinPath(&outer_buffer, ancestor[0..ancestor_len], mine) orelse return error.SkipZigTest;
    const outer = outer_buffer[0..outer_len];
    if (!testMakeDir(outer)) return error.SkipZigTest;
    defer testRemoveDir(outer);

    const victim = testSpawnSleeper() orelse return error.SkipZigTest;
    var reaped = false;
    defer if (!reaped) testKillAndReap(victim);

    var number: [32]u8 = undefined;
    const victim_text = try std.fmt.bufPrint(&number, "{d}", .{victim});
    try std.testing.expect(writeFileAt(outer, "cgroup.procs", victim_text));
    try std.testing.expect(testCgroupHolds(outer, victim));

    const dir_fd = testOpenDir(outer) orelse return error.SkipZigTest;
    defer _ = linux.close(dir_fd);

    // One member, signalled once. The count is what bounds the retry loop in
    // `killMembers`, so a fallback that answered zero for a cgroup with a
    // process in it would stop before it had killed anything.
    try std.testing.expectEqual(@as(?usize, 1), signalMembers(dir_fd));

    const status = testReap(victim) orelse return error.SkipZigTest;
    reaped = true;
    try std.testing.expect(linux.W.IFSIGNALED(status));
    try std.testing.expectEqual(linux.SIG.KILL, linux.W.TERMSIG(status));

    // A directory with no `cgroup.procs` is not a cgroup, and the answer is
    // "cannot tell" and never "empty". `/proc/self` is a directory of this
    // process's own with no such file in it.
    const not_a_cgroup = testOpenDir("/proc/self") orelse return error.SkipZigTest;
    defer _ = linux.close(not_a_cgroup);
    try std.testing.expectEqual(@as(?usize, null), signalMembers(not_a_cgroup));
}
