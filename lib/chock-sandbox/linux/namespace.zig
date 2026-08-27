//! The user, mount, and network namespaces. A user namespace is what gives an ordinary
//! user the right to make the other two.

const std = @import("std");
const linux = std.os.linux;

/// How the sandboxed process reaches the network.
///
/// **Every name here states what the process can reach, and no name states how
/// the kernel does it.** Before 2026-08-24 the first two were called `isolated`
/// and `brokered`, and the project owner read the first as a network that is
/// filtered and the second as the one that is cut off, which is the opposite of
/// what each did. "isolated" describes the namespace and says nothing about
/// what comes out of it. `none`, `filtered` and `host` answer the one question
/// a reader has, which is what this process can talk to.
///
/// `none` and `filtered` take **the same closed network namespace**. The
/// difference between them is one descriptor, not one route: see `filtered`.
pub const Network = enum {
    /// **Nothing can be reached.** Its own network namespace, with no route out
    /// and no descriptor to ask on.
    ///
    /// This is the default. A tool call gets this.
    none,
    /// **Only the hosts a policy names can be reached, one connection at a
    /// time.** Its own network namespace, and a unix socket to the parent. The
    /// process cannot open a connection. It asks the parent, and the parent
    /// sends back a connected socket for a host that a policy permits.
    ///
    /// **The namespace here is the same one `none` takes, and that is the whole
    /// point.** A `filtered` process has no route out of its own accord. What
    /// it has in addition is one descriptor, and one only, on a socket pair
    /// whose other end is held on the far side of the boundary. See
    /// `lib/chock-sandbox/linux/netbroker.zig` for the exchange, and
    /// `Sandbox.Config.net_broker` for who answers it.
    ///
    /// **An empty policy is not the same thing as `none`, and a caller must not
    /// read it as one.** Measured on 2026-08-24, in this tree: making this the
    /// default of `Sandbox.Config.network` failed 69 tests. `spawn` refuses a
    /// `filtered` config that names no broker with `error.NetBrokerMissing`,
    /// before it forks, so every caller that omits one stops running at all;
    /// and the filter below takes `connect` away, which is a second, separate
    /// change. See `Sandbox.Config.net_broker`.
    ///
    /// It is also **stricter than `none` on system calls**, not looser: the
    /// Linux driver turns on `seccomp.Options.block_connect` for this case, so
    /// the process cannot aim a granted descriptor at anything else. See that
    /// option's own comment for the measurement that made it necessary.
    filtered,
    /// **Everything the host can reach.** The network namespace of the host.
    /// Nothing is removed. Only the broker gets this, and only for an action
    /// that the user approved.
    host,
};

pub const Options = struct {
    /// Which network the process gets. Defaults to `.none`, so a caller that
    /// omits this field gets no network, not the host's.
    network: Network = .none,
    /// Give the process its own mount tree.
    mount: bool = true,
};

pub const Error = error{
    /// The kernel refused the namespace. A policy can turn off a user namespace for an
    /// ordinary user. Report this to the user. Do not continue without the layer.
    NotPermitted,
    /// The caller has more than one thread. The kernel refuses `CLONE_NEWUSER` once a
    /// process has started a second thread. Call `enter` before starting any other
    /// thread, or move the call to a fresh single threaded process.
    MultiThreaded,
    /// A map file could not be written.
    MapFailed,
    /// The kernel returned an errno that does not match any of the cases above. The
    /// caller has no specific recovery for this and should report it as a bug.
    Unexpected,
};

/// Enter the namespaces. The caller must have one thread only, because the kernel
/// refuses `CLONE_NEWUSER` from a process with more than one thread.
pub fn enter(options: Options) Error!void {
    const uid = linux.getuid();
    const gid = linux.getgid();

    // NEWPID and NEWIPC are not optional and have no configuration field, the same
    // as NEWNET below. Without NEWPID every process the user owns is a legal
    // signal target, including chockd itself, and prlimit64 and setpriority reach
    // arbitrary host processes too. Without NEWIPC, System V shared memory,
    // message queues, and semaphores cross the sandbox boundary in both
    // directions: host data can be read in, and a sandboxed process can write
    // into a host segment as a covert channel the network namespace never sees.
    var flags: usize = linux.CLONE.NEWUSER | linux.CLONE.NEWPID | linux.CLONE.NEWIPC;
    if (options.mount) flags |= linux.CLONE.NEWNS;
    switch (options.network) {
        // **`filtered` takes the same closed namespace as `none`, and it always
        // will.** The socket to the parent is a descriptor, not a route: a
        // `filtered` process can still open no connection of its own, which is
        // exactly what makes asking the parent the only way out. See `Network`.
        .none, .filtered => flags |= linux.CLONE.NEWNET,
        .host => {},
    }

    switch (linux.errno(linux.unshare(flags))) {
        .SUCCESS => {},
        .PERM, .NOSPC => return error.NotPermitted,
        .INVAL => return error.MultiThreaded,
        else => return error.Unexpected,
    }

    try writeIdMaps(uid, gid);
}

/// Map the user to itself inside the new user namespace. Without a map, the process has
/// the overflow user and cannot own a file.
pub fn writeIdMaps(uid: linux.uid_t, gid: linux.gid_t) Error!void {
    var buffer: [64]u8 = undefined;

    // The write to setgroups must happen first. Without it the write to gid_map fails
    // with EPERM, because a user could otherwise drop a group to gain access.
    try writeFile("/proc/self/setgroups", "deny");

    const uid_line = std.fmt.bufPrint(&buffer, "{d} {d} 1", .{ uid, uid }) catch unreachable;
    try writeFile("/proc/self/uid_map", uid_line);

    const gid_line = std.fmt.bufPrint(&buffer, "{d} {d} 1", .{ gid, gid }) catch unreachable;
    try writeFile("/proc/self/gid_map", gid_line);
}

// Zig 0.16 moved the hosted file API behind std.Io, and this file already calls the
// kernel by hand everywhere else, so a map line goes through linux.open/write/close
// directly rather than pull std.Io into a namespace module.
fn writeFile(path: [*:0]const u8, contents: []const u8) Error!void {
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return error.MapFailed;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    // One write must carry the whole line. The kernel refuses a partial map line.
    const written = linux.write(fd, contents.ptr, contents.len);
    if (linux.errno(written) != .SUCCESS or written != contents.len) return error.MapFailed;
}

test "an id map line maps one id to itself" {
    var buffer: [64]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{d} {d} 1", .{ 1000, 1000 });
    try std.testing.expectEqualStrings("1000 1000 1", line);
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    // **The first, not the last.** A pivot can only fail after a mount tree
    // that did not, so a later call overwriting an earlier one would replace
    // the fault that explains the run with the fault it caused.
    var diag: ?Diagnostic = null;
    note(&diag, .mount_call, .PERM);
    note(&diag, .pivot_root, .NOENT);
    try std.testing.expectEqual(Diagnostic.Call.mount_call, diag.?.call);
    try std.testing.expectEqual(linux.E.PERM, diag.?.errno);

    // A caller that asked for no diagnostic is the ordinary case, and it must
    // reach no store at all rather than write into a scratch value.
    note(null, .pivot_root, .NOENT);
}

test "a diagnostic names the call and the errno, and allocates nothing" {
    // The two facts `error.Unexpected` throws away. Rendering happens here, at
    // a caller with a buffer, because the sites that fill one run in the child
    // after `clone` where there is no allocator.
    var buffer: [128]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{
        Diagnostic{ .call = .overlay_mount, .errno = .NODEV },
    });
    try std.testing.expectEqualStrings("the overlay mount failed: NODEV", line);

    // **No two calls read the same.** That is the fact worth pinning: a
    // reader has to be able to tell which one failed. An underscore is not
    // the test, because `mount_setattr` and `pivot_root` are what those calls
    // are really named and spelling them any other way would help nobody.
    const calls = std.enums.values(Diagnostic.Call);
    for (calls, 0..) |call, i| {
        try std.testing.expect(call.text().len > 0);
        for (calls[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, call.text(), other.text()));
        }
    }
}

/// One entry in the sandbox's own mount tree. Every entry describes a mount;
/// none of them perform one. `buildRoot` is the only place that ever calls
/// `mount(2)`, so a caller can build a full mount list, including an overlay
/// entry, from an ordinary, unprivileged process, and hand it to
/// `Sandbox.spawn` without ever entering a namespace itself.
pub const Mount = union(enum) {
    /// `source`, a path outside the sandbox, appears at `target` inside it.
    bind: Bind,
    /// An overlayfs mount, merging a read only lower layer and a read write
    /// upper layer at `target`. See `Overlay`'s own doc comment.
    overlay: Overlay,
    /// A fresh procfs, showing this sandbox's own processes and no other.
    /// See `Proc`'s own doc comment.
    proc: Proc,
    /// One file whose bytes must not be inside the sandbox at all. See
    /// `Deny`'s own doc comment.
    deny: Deny,

    pub const Bind = struct {
        /// The path outside the sandbox.
        source: []const u8,
        /// The path inside the sandbox. Chock uses the real path of the
        /// project, so that a path in a compiler message is a path the user
        /// can open.
        target: []const u8,
        read_only: bool = false,
    };

    /// A project with no git of its own gets an overlayfs mount instead of a
    /// worktree. `lower` stays read only, and
    /// every write lands in `upper`, with `work` as overlayfs's own scratch
    /// directory. `target` is where the merged view appears inside the
    /// sandbox, the project's own real path.
    pub const Overlay = struct {
        lower: []const u8,
        upper: []const u8,
        work: []const u8,
        target: []const u8,
    };

    /// A fresh procfs at `target`, and never the host's own.
    ///
    /// **An ordinary program assumes `/proc` exists**, the same assumption the
    /// `/dev/null` bind mount in `lib/chock-core/tools.zig` already answers.
    /// Measured on 2026-08-21: `zig build-exe` inside the sandbox answers
    ///
    ///   error: unable to find zig self exe path: FileNotFound
    ///
    /// because a compiler reads `/proc/self/exe` to find its own installation,
    /// and Python, Perl and Go each read something under `/proc` for the same
    /// class of reason. So without this no real toolchain runs here at all.
    ///
    /// **It shows this sandbox's own processes and no other.** `enter` always
    /// takes a PID namespace, and a procfs mounted inside one lists only the
    /// processes of that namespace. So this is not a window onto the host: it
    /// is the sandbox looking at itself. `test/sandbox/escape.zig` holds the
    /// test that says so.
    ///
    /// Mounted read only, with `nosuid`, `nodev` and `noexec`, because nothing
    /// a tool call does needs to write a kernel interface, and `/proc/sys` is
    /// the part of this tree with real reach.
    ///
    /// **The global files that describe the host read empty.** See
    /// `masked_proc_entries`. The process list needs nothing of the kind: a
    /// procfs mounted inside a PID namespace lists that namespace's own
    /// processes and no other.
    pub const Proc = struct {
        target: []const u8 = "/proc",
    };

    /// One file the sandbox must not hold the bytes of. `target` is the path
    /// inside the sandbox, and there is no source: `buildRoot` binds
    /// `deny_notice` over it instead, the same mechanism `maskProcEntries`
    /// already uses for `/proc`.
    ///
    /// **This is the only layer that keeps a secret out of a tool call, and
    /// the reason is one sentence: bytes that never enter the process cannot
    /// be missed.** `lib/chock-core/redact.zig` searches an outbound request
    /// for a value it already knows, which helps with an accident and stops no
    /// attack, because an agent that can read a file can also spell it out one
    /// character at a time. A mount is not a filter. There is nothing left to
    /// find.
    ///
    /// **Landlock cannot do this and never will.** Landlock rights accumulate
    /// on a nested path and are never narrowed by a wider rule, so a file
    /// under a read write project directory cannot be subtracted from it. See
    /// `lib/chock-workspace/Workspace.zig`, which writes the same rule down
    /// beside the rules it builds.
    ///
    /// **A denied path always exists inside the sandbox, and it reads as
    /// `deny_notice`.** It cannot be made absent: a bind mount covers a path,
    /// and no unprivileged operation removes one name from a directory that is
    /// itself a mount of the project. So the choice is what the covering file
    /// holds, and an empty file is the one answer that must not be given: an
    /// agent that reads an empty `.env` concludes the project has no
    /// configuration and acts on that, which costs many turns. A line that
    /// says what happened costs one.
    ///
    /// **A file only, never a directory.** `buildRoot` refuses a target that
    /// is a directory with `error.DenyTargetIsDirectory` rather than covering
    /// it with something. A bind of an empty directory would read as "this
    /// project keeps no credentials here", which is the same confusion an
    /// empty file makes, with no place to put a line of text that corrects it.
    /// `lib/chock-workspace/deny.zig` refuses a directory earlier still, when
    /// it reads the project's own list, so this refusal is for the path that
    /// became a directory after that read.
    ///
    /// **A target that does not exist yet is created, empty, and then
    /// covered.** So a project that denies a file it does not have today is
    /// still protected on the day it makes one, and the protection does not
    /// depend on a race between the mount and the file. See
    /// `applyDenyMounts` for what that leaves behind.
    pub const Deny = struct {
        /// The path inside the sandbox, absolute, naming one file.
        target: []const u8,
    };
};

/// What a denied path holds inside the sandbox. See `Mount.Deny` for why this
/// is a sentence and not an empty file.
///
/// **It names no policy file.** This library reads no `chock.zon` and imports
/// no other chock library, so the words here say
/// what is true of the mount alone. `lib/chock-core/tools.zig` is the layer
/// that knows which block of which file asked for this, and its own refusal
/// names both.
pub const deny_notice = "chock: this file is denied by the project. Its bytes are not in this sandbox.\n";

/// The name of the file every deny mount is a bind of. It exists only while
/// `applyDenyMounts` runs, under the sandbox root, and the name is gone before
/// anything runs inside the sandbox. Separate from
/// `proc_mask_source_name` because the two hold different bytes.
const deny_notice_source_name = ".chock-denied";

/// A writable area the sandbox owns, held in memory, with a hard cap on how
/// much it can hold. **This is the only capacity limit an unprivileged process
/// can put on a filesystem**, and it is the answer to the one row of
/// `rlimits.zig`'s own table that used to say "not solved".
///
/// ## Why a tmpfs, and why nothing else
///
/// `RLIMIT_FSIZE` bounds **one file**. Ten thousand files of one byte each
/// still fill a filesystem, and a filesystem that fills breaks the machine for
/// everything else on it, including the session log that is supposed to
/// explain what happened. Of the ways to bound total bytes:
///
/// * **An XFS or ext4 project quota needs privilege.** Chock has none.
/// * **A loopback image needs a loop device.** Chock cannot make one.
/// * **The cgroup `io` controller bounds bandwidth, not capacity.** A slow
///   writer still fills a disk, only later.
/// * **A tmpfs with a `size=` option needs nothing at all**, inside the mount
///   namespace the sandbox already takes. Measured on 2026-08-22, on Linux
///   6.18.42, in exactly the namespace shape `enter` makes, with the invoking
///   uid mapped to itself and never to root: the mount succeeded, its root
///   came out owned by that same uid, and a write past the cap answered
///   `ENOSPC`.
///
/// ## The bound this shares with `memory.max`, which a later reader must not
/// raise on its own
///
/// **A tmpfs page is a memory page, and it is charged to the cgroup of
/// whichever process dirtied it.** So the capacity of these areas comes out of
/// the same budget `rlimits.default_memory_bytes` names, and a tmpfs as large
/// as that budget turns a full disk into an out of memory kill.
///
/// Measured on 2026-08-22, with `memory.max` at 128 MiB and one program
/// filling a tmpfs one page at a time:
///
/// * tmpfs `size=64M`: filled to exactly 64 MiB, stopped with `ENOSPC`, exited
///   0, and `memory.events` counted no kill.
/// * tmpfs `size=96M`: the same, cleanly.
/// * tmpfs `size=120M`: the same, cleanly.
/// * tmpfs `size=128M`, equal to `memory.max`: **killed with `SIGKILL`**, and
///   `memory.events` counted `oom_kill 1`.
/// * tmpfs `size=160M`: the same kill.
///
/// So the two numbers are one decision and not two.
/// `rlimits.default_scratch_bytes` sits far below
/// `rlimits.default_memory_bytes` on purpose, and
/// `rlimits.Limits.scratchFitsUnderMemory` is that rule written down, with a
/// test that fails if a later reader raises one number and not the other.
///
/// ## A page is the smallest thing a file can cost
///
/// Measured on the same machine, whose pages are 64 KiB: a tmpfs of `size=16M`
/// held **256 files**, and it held 256 of them whether each one carried 1 byte,
/// 4096 bytes or 65536 bytes. A file costs a whole page whatever is in it, so
/// the number of files an area holds is its cap divided by the page size, and a
/// machine with 4 KiB pages holds sixteen times as many files in the same cap
/// as this one does. **A number of files is never the thing to reason about
/// here. A number of bytes is.**
///
/// ## What is mounted, and what is deliberately not
///
/// `nosuid` and `nodev`, because nothing a tool call writes into a scratch area
/// has any business being a set-user-ID binary or a device node.
///
/// **Not `noexec`, and that is a decision.** A scratch area stands in for
/// `TMPDIR`, and an ordinary build writes a program there and runs it: a
/// `configure` script and `libtool` both do. `noexec` would refuse that and buy
/// nothing, because the workspace beside it is writable and is not `noexec`
/// either, so a program that wants to run what it just wrote already can.
pub const Scratch = struct {
    /// The path inside the sandbox. Created by `mountScratch` if it is not
    /// there, the same way a mount target is.
    target: []const u8,
};

/// `TMPFS_MAGIC` from `uapi/linux/magic.h`. `scratchIsFull` reads it so that a
/// full **host** filesystem, reached through some path this code did not mount,
/// can never be reported as one of the sandbox's own areas.
pub const tmpfs_magic: u64 = 0x01021994;

/// The kernel's `struct statfs`, for the one call `scratchIsFull` makes. Zig's
/// standard library declares neither the type nor the call, so the ABI is
/// written out here by hand from the kernel's own `asm-generic/statfs.h`, the
/// same way `MountAttr` below is.
///
/// This is the 64 bit layout. Every target this project builds for is 64 bit,
/// where `fstatfs` and `fstatfs64` carry the same structure.
const Statfs = extern struct {
    f_type: u64,
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]u32,
    f_namelen: u64,
    f_frsize: u64,
    f_flags: u64,
    f_spare: [4]u64,
};

/// The faults `buildRoot`, `pivotInto`, and their private helpers can return.
pub const MountError = error{
    /// The kernel refused a mount, a path creation, or a pivot for lack of
    /// privilege.
    NotPermitted,
    /// The allocator could not satisfy a request. This is our own bug, the same
    /// as anywhere else `OutOfMemory` shows up in hosted code, not a kernel fault.
    OutOfMemory,
    /// A mount's source path does not exist, so its type cannot be read to decide
    /// whether the target should be a file or a directory.
    SourceMissing,
    /// `mount_setattr` needs kernel 5.12 or later. An older kernel returns ENOSYS.
    /// A read only mount cannot be made on this host, and the sandbox must not
    /// start and silently drop that protection instead.
    KernelTooOld,
    /// The running kernel does not support an unprivileged overlay mount
    /// inside a user namespace, or the caller has not entered one yet.
    /// Rootless overlayfs needs kernel 5.11 or later. Reported plainly,
    /// never a silent fall back to a bind mount or a plain copy.
    OverlayNotSupported,
    /// A `Mount.Deny` names a path that is a directory inside the sandbox. See
    /// `Mount.Deny` for why a directory is refused instead of covered, and
    /// `lib/chock-workspace/deny.zig` for the earlier refusal that catches
    /// almost every one of these before a sandbox is ever built.
    ///
    /// **The sandbox does not start.** A tool call that ran with the denial
    /// dropped would read the very bytes the project asked to keep out, so the
    /// only safe answer is to refuse the call.
    DenyTargetIsDirectory,
    /// The kernel returned an errno with no specific recovery. Reported as a bug.
    Unexpected,
};

/// Which call the kernel refused, and what it answered.
///
/// **`error.Unexpected` alone throws away the only two facts that identify the
/// fault.** Before this type, every one of those sites printed the errno to the
/// terminal and then returned the bare error, which put a library in charge of
/// what a person sees and left a caller that is not a terminal with nothing.
///
/// **This owns no memory and allocates nothing.** The hardest callers run in
/// the child after `clone`, where there is no allocator and no way to unwind,
/// so the type holds two enumerations and nothing else. A reader turns it into
/// words with `format`, at the caller, which is where the decision belongs.
pub const Diagnostic = struct {
    call: Call,
    errno: linux.E,

    /// The calls that can answer an errno this code cannot interpret. Named for
    /// what was being done, not for the system call alone, because `open` says
    /// much less than "open on a mount target".
    pub const Call = enum {
        proc_mask_file,
        proc_entry_stat,
        deny_notice_file,
        deny_notice_write,
        deny_target_stat,
        overlay_mount,
        scratch_mount,
        scratch_open,
        mount_source_stat,
        mount_setattr,
        mount_target_mkdir,
        mount_target_open,
        mount_call,
        pivot_root,
        chdir_after_pivot,
        old_root_umount,

        /// What was being done, as a phrase that reads after "chock: ".
        pub fn text(self: Call) []const u8 {
            return switch (self) {
                .proc_mask_file => "open on the proc mask file",
                .proc_entry_stat => "statx on a proc entry",
                .deny_notice_file => "open on the deny notice file",
                .deny_notice_write => "the write of the deny notice",
                .deny_target_stat => "statx on a denied path",
                .overlay_mount => "the overlay mount",
                .scratch_mount => "the scratch area mount",
                .scratch_open => "open on a scratch area",
                .mount_source_stat => "statx on a mount source",
                .mount_setattr => "mount_setattr",
                .mount_target_mkdir => "mkdirat on a mount target",
                .mount_target_open => "open on a mount target",
                .mount_call => "the mount call",
                .pivot_root => "pivot_root",
                .chdir_after_pivot => "chdir after pivot_root",
                .old_root_umount => "umount2 of the old root",
            };
        }
    };

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{s} failed: {s}", .{ self.call.text(), @tagName(self.errno) });
    }
};

/// Fill `diag` when the caller asked for one.
///
/// **The first fault is kept, not the last.** A later call can only fail
/// because an earlier one did, so the first is the one that explains the rest.
fn note(diag: ?*?Diagnostic, call: Diagnostic.Call, errno: linux.E) void {
    const slot = diag orelse return;
    if (slot.* != null) return;
    slot.* = .{ .call = call, .errno = errno };
}

/// Whether a mount target should be created as a file or a directory. A bind
/// mount needs a target of the same kind as its source, or the mount call fails
/// with ENOTDIR.
const PathKind = enum { directory, file };

/// Build the mount tree. Call this after `enter` with `mount` set.
pub fn buildRoot(
    allocator: std.mem.Allocator,
    root: []const u8,
    mounts: []const Mount,
    diag: ?*?Diagnostic,
) MountError!void {
    // Make every mount private first. Without this, a mount inside the namespace can
    // travel back to the mount tree of the host.
    try mountCall(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0, diag);

    // The new root must be a mount point of its own before `pivot_root` accepts it.
    const root_z = try allocator.dupeZ(u8, root);
    defer allocator.free(root_z);
    try mountCall(root_z, root_z, null, linux.MS.BIND | linux.MS.REC, 0, diag);

    for (mounts) |m| {
        switch (m) {
            .bind => |b| try buildBindMount(allocator, root, b, diag),
            .overlay => |o| try buildOverlayMount(allocator, root, o, diag),
            .proc => |p| try buildProcMount(allocator, root, p, diag),
            // A second pass, below. See `applyDenyMounts`.
            .deny => {},
        }
    }

    // Last, and in a pass of its own, so a denial wins whatever order the
    // caller put the list in. See `applyDenyMounts`.
    try applyDenyMounts(allocator, root, mounts, diag);
}

/// Cover every `Mount.Deny` in `mounts` with a file that holds `deny_notice`.
/// See `Mount.Deny` for what a denial is worth and what it costs.
///
/// **A pass of its own, after every other mount, and that is the whole
/// mechanism.** The workspace binds the project's working tree in one mount,
/// so a denial written before it would be covered by it and would protect
/// nothing. Running the denials last means a caller cannot lose the property
/// by reordering a list. `maskProcEntries` is the same trick against `/proc`,
/// and this function is that trick given a caller.
///
/// One notice file is made under `root` and bound over every target, then its
/// name is removed: a mount holds the file itself, so each denial stays after
/// the name is gone, and the sandbox root is left with nothing extra in it.
///
/// **A project that denies nothing pays nothing.** The function returns before
/// it makes any file at all, so a sandbox with no `Mount.Deny` in its list
/// makes exactly the calls it always made.
///
/// **What a created target leaves behind.** A denied path that is not in the
/// project yet is created here as an empty file, and that creation goes
/// through the workspace mount, so it lands in the worktree checkout or in the
/// overlay's upper layer and stays there after the mount namespace is gone. It
/// is one empty file with a name the project itself asked to deny, it can be
/// neither written nor removed while a tool call runs, and it never reaches
/// the user's repository, which only a commit does. That is the price of a
/// protection that does not lapse the moment the agent makes the file itself.
///
/// **A target that already exists is never opened here.** The kind is read
/// with `statx` and the bind follows. An `open` with `O_CREAT` on an existing
/// file would trigger an overlayfs copy up, which would copy the very bytes
/// this function exists to keep out of reach into the session's own scratch
/// directory.
fn applyDenyMounts(
    allocator: std.mem.Allocator,
    root: []const u8,
    mounts: []const Mount,
    diag: ?*?Diagnostic,
) MountError!void {
    var any = false;
    for (mounts) |m| {
        if (m == .deny) {
            any = true;
            break;
        }
    }
    if (!any) return;

    const source = try std.fs.path.join(allocator, &.{ root, deny_notice_source_name });
    defer allocator.free(source);

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);
    try makeNoticeFile(source_z.ptr, diag);
    // Runs whichever way this function leaves, the same as `maskProcEntries`.
    // A failure to remove the name is not a failure of the sandbox: the file
    // holds one printable line, and it is inside the session's own root.
    defer _ = linux.unlinkat(linux.AT.FDCWD, source_z.ptr, 0);

    for (mounts) |m| {
        const deny = switch (m) {
            .deny => |d| d,
            .bind, .overlay, .proc => continue,
        };

        const target = try std.fs.path.join(allocator, &.{ root, deny.target });
        defer allocator.free(target);

        const target_z = try allocator.dupeZ(u8, target);
        defer allocator.free(target_z);

        switch (try existingPathKind(target_z.ptr, .deny_target_stat, diag)) {
            // Nothing there yet. Make an empty file to bind over, so the
            // denial holds for the file the agent has not made yet.
            .missing => try makePath(allocator, target, .file, diag),
            .directory => return error.DenyTargetIsDirectory,
            .file => {},
        }

        // No `MS.REC`: one file, which has nothing under it.
        try mountCall(source_z, target_z, null, linux.MS.BIND, 0, diag);
        // So a write to a denied path is refused rather than editing the one
        // notice file every other denial in this sandbox also reads.
        try markReadOnly(target_z, diag);
    }
}

/// Make `path` a file holding exactly `deny_notice`, whatever was there
/// before it.
///
/// `makeFile` cannot serve here, for the same reason `makeEmptyFile` cannot
/// serve `maskProcEntries`: `makeFile` never truncates, on purpose, because
/// the content of a mount target does not matter to the mount that covers it.
/// The content of this one is what every denied path in the sandbox reads.
fn makeNoticeFile(path: [*:0]const u8, diag: ?*?Diagnostic) MountError!void {
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .deny_notice_file, err);
            return error.Unexpected;
        },
    }
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var written: usize = 0;
    while (written < deny_notice.len) {
        const rc = linux.write(fd, deny_notice.ptr + written, deny_notice.len - written);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            .PERM, .ACCES => return error.NotPermitted,
            else => |err| {
                note(diag, .deny_notice_write, err);
                return error.Unexpected;
            },
        }
        // A write of zero bytes to a regular file makes no progress and would
        // loop for ever, so it reads as a fault rather than as a retry.
        if (rc == 0) {
            note(diag, .deny_notice_write, .IO);
            return error.Unexpected;
        }
        written += rc;
    }
}

/// Apply one bind mount, `b`, under `root`. Exactly the mount `buildRoot`
/// always made, unchanged: this is only `buildRoot`'s own loop body, pulled
/// out so the loop can switch on `Mount`'s three kinds.
fn buildBindMount(allocator: std.mem.Allocator, root: []const u8, b: Mount.Bind, diag: ?*?Diagnostic) MountError!void {
    const target = try std.fs.path.join(allocator, &.{ root, b.target });
    defer allocator.free(target);

    const source_z = try allocator.dupeZ(u8, b.source);
    defer allocator.free(source_z);

    // chock.zon is protected by binding a file over a file, not a directory
    // over a directory, so the target must match whichever kind the source
    // actually is.
    const kind: PathKind = if (try sourceIsDirectory(source_z, diag)) .directory else .file;
    try makePath(allocator, target, kind, diag);

    const target_z = try allocator.dupeZ(u8, target);
    defer allocator.free(target_z);

    try mountCall(source_z, target_z, null, linux.MS.BIND | linux.MS.REC, 0, diag);

    if (b.read_only) try markReadOnly(target_z, diag);
}

/// Mount a fresh procfs at `p.target` under `root`. See `Mount.Proc`.
///
/// The kernel gives a procfs mounted from inside a PID namespace the view of
/// that namespace, so this needs no filtering of its own: `enter` always takes
/// `CLONE_NEWPID`, and the processes in it are this sandbox's own.
fn buildProcMount(allocator: std.mem.Allocator, root: []const u8, p: Mount.Proc, diag: ?*?Diagnostic) MountError!void {
    const target = try std.fs.path.join(allocator, &.{ root, p.target });
    defer allocator.free(target);

    try makePath(allocator, target, .directory, diag);

    const target_z = try allocator.dupeZ(u8, target);
    defer allocator.free(target_z);

    try mountCall(
        "proc",
        target_z,
        "proc",
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        0,
        diag,
    );
    // Before the mount is made read only, because every mask is itself a
    // mount and `markReadOnly` is recursive: this order gives the empty
    // files the same read only, `nosuid`, `nodev` mount attributes as the
    // procfs they sit in.
    try maskProcEntries(allocator, root, target, diag);
    // Read only after the mount, and not a mount flag, for the same reason
    // `buildBindMount` marks a bind mount afterwards: `mount_setattr` is what
    // this file uses everywhere to make a mount read only.
    try markReadOnly(target_z, diag);
}

/// The global files of a procfs that read empty inside the sandbox.
///
/// **This reduces a surface. It is not a boundary, and nothing may be built as
/// though it were.** The list is a list of names, the same shape as the git
/// shim in `lib/chock-broker/git_shim.zig` and for the same reason: the next
/// kernel adds a file nobody here has heard of, and that file will read
/// through. A denylist fails for that reason. What stops an attack is the
/// layers: the namespaces, the Landlock rules and the seccomp filter, every
/// one of which holds whether or not a name below is spelled correctly.
///
/// **Measured, and this is what a red team session read out of `/proc` on
/// 2026-08-21**: `cmdline` gave `lsm=landlock,yama,bpf`, the NixOS system
/// store path and the host name; `version` gave the kernel version and the
/// compiler that built it; `kallsyms` gave every symbol name; `config.gz`
/// gave the kernel configuration. The `lsm=` line is the one that matters,
/// because it hands a reader the exact list of enforcement mechanisms to
/// work around. The value of masking is that the sandbox stops describing
/// itself for free, not that a determined reader learns nothing.
///
/// **`/proc/self` is deliberately absent, and must stay absent.** It is why
/// `/proc` is mounted at all: a compiler reads `/proc/self/exe` to find its
/// own installation, and a mask over that tree brings back "unable to find
/// zig self exe path", which is a whole toolchain that cannot run. See
/// `Mount.Proc`.
///
/// **`cpuinfo` and `meminfo` are deliberately absent too.** Both describe
/// the host, and both are read by ordinary build tools: `nproc` counts
/// processors with the first, and a compiler sizes its own job pool with the
/// second. Masking them buys a little and costs every parallel build, so
/// they are left, and this comment is the record of that choice rather than
/// an oversight.
///
/// Every name here is a regular file. `maskProcEntries` skips one that is
/// absent on the running kernel, because several are behind a kernel
/// configuration option, and skips a directory, because a file cannot be
/// bound over one.
pub const masked_proc_entries: []const []const u8 = &.{
    // What the red team session read. `cmdline` names the enforcement
    // mechanisms, the system store path and the host name.
    "cmdline",
    "version",
    "kallsyms",
    "config.gz",
    // Kernel memory, symbol addresses and module names: what an exploit
    // needs to aim.
    "kcore",
    "modules",
    "iomem",
    "ioports",
    "mtrr",
    // Kernel internals that name host processes, host timers and host
    // hardware, in files the PID namespace does not filter.
    "sched_debug",
    "timer_list",
    "latency_stats",
    "interrupts",
    "schedstat",
    "slabinfo",
    "vmallocinfo",
    "keys",
    "key-users",
    // A write to `sysrq-trigger` reboots the machine, and a read of `kmsg`
    // takes the host's kernel log away from whoever reads it next. Only the
    // read half is this list's work: a write to any part of this mount is
    // already refused, because the whole mount is read only.
    "sysrq-trigger",
    "kmsg",
};

/// The name of the empty file each mask is a bind mount of. It exists only
/// while `maskProcEntries` runs, under the sandbox root, and the name is
/// gone before anything runs inside the sandbox.
const proc_mask_source_name = ".chock-proc-mask";

/// Bind an empty file over each of `masked_proc_entries` inside the procfs at
/// `proc_target`. See that list for what this is worth and what it is not.
///
/// One empty file is made under `root` and bound over every entry, then its
/// name is removed. A mount holds the file itself, so each mask stays after
/// the name is gone, and the sandbox root is left with nothing extra in it.
fn maskProcEntries(allocator: std.mem.Allocator, root: []const u8, proc_target: []const u8, diag: ?*?Diagnostic) MountError!void {
    const source = try std.fs.path.join(allocator, &.{ root, proc_mask_source_name });
    defer allocator.free(source);

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);
    try makeEmptyFile(source_z.ptr, diag);
    // Runs whichever way this function leaves. A failure to remove the name
    // is not a failure of the sandbox: the file is empty, and it is inside
    // the session's own root.
    defer _ = linux.unlinkat(linux.AT.FDCWD, source_z.ptr, 0);

    for (masked_proc_entries) |name| {
        const target = try std.fs.path.join(allocator, &.{ proc_target, name });
        defer allocator.free(target);

        const target_z = try allocator.dupeZ(u8, target);
        defer allocator.free(target_z);

        switch (try existingPathKind(target_z.ptr, .proc_entry_stat, diag)) {
            // A kernel built without the option that makes this file.
            .missing => continue,
            // A file cannot be bound over a directory. Nothing in
            // `masked_proc_entries` is one today, and a kernel that turns
            // one into a directory must not stop the sandbox from starting.
            .directory => continue,
            .file => {},
        }

        // No `MS.REC`: one file, which has nothing under it.
        try mountCall(source_z, target_z, null, linux.MS.BIND, 0, diag);
    }
}

/// Make `path` an empty file, whatever was there before it.
///
/// `makeFile` cannot serve here. It never truncates, on purpose, because the
/// content of a mount target does not matter to the mount that covers it. The
/// content of this one is the whole point: every masked entry reads it, so a
/// file left over from an earlier run must not be what a reader gets.
fn makeEmptyFile(path: [*:0]const u8, diag: ?*?Diagnostic) MountError!void {
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .proc_mask_file, err);
            return error.Unexpected;
        },
    }
    _ = linux.close(@intCast(fd_rc));
}

/// What is at `path`, when the answer "nothing" is a fact the caller acts on
/// rather than a fault. Unlike `sourceIsDirectory`, an absent path is an
/// answer here: `maskProcEntries` skips an entry a kernel was built without,
/// and `applyDenyMounts` makes a file for a path the project does not hold
/// yet. `call` is what a failure is reported as, so a reader learns which of
/// the two walks was refused.
///
/// **Anything that is not a directory reads as a file**, which is what both
/// callers want. A denied path that is a symbolic link is followed, so a link
/// aimed at a file is covered as that file's own path is, and a link aimed at
/// a directory is refused as a directory is.
fn existingPathKind(
    path: [*:0]const u8,
    call: Diagnostic.Call,
    diag: ?*?Diagnostic,
) MountError!enum { missing, directory, file } {
    var stat_buf: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true }, &stat_buf);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOENT, .NOTDIR => return .missing,
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, call, err);
            return error.Unexpected;
        },
    }
    if ((stat_buf.mode & linux.S.IFMT) == linux.S.IFDIR) return .directory;
    return .file;
}

/// Apply one overlay mount, `o`, under `root`: make its target a directory,
/// then mount there. See `mountOverlay` for the real mount call, which this
/// function also uses to give `test/workspace/overlay_helper.zig` a real
/// overlay mount to test against directly, at a target that is not under any
/// `root` at all.
fn buildOverlayMount(allocator: std.mem.Allocator, root: []const u8, o: Mount.Overlay, diag: ?*?Diagnostic) MountError!void {
    const target = try std.fs.path.join(allocator, &.{ root, o.target });
    defer allocator.free(target);

    try makePath(allocator, target, .directory, diag);

    try mountOverlay(allocator, .{
        .lower = o.lower,
        .upper = o.upper,
        .work = o.work,
        .target = target,
    }, diag);
}

/// Mount an overlayfs merging `o.lower` (read only) and `o.upper` (read
/// write) at `o.target`, with `o.work` as overlayfs's own scratch directory.
/// `o.target` must already exist as a directory: `buildOverlayMount` makes it
/// first, under a sandbox root; `test/workspace/overlay_helper.zig` calls
/// this directly, with a target it made itself, to get a real overlay mount
/// outside any sandbox root at all, the same way it needs one to test
/// `lib/chock-workspace/overlay.zig`'s own upper layer diff.
///
/// `userxattr` is always in the mount options. Without it, overlayfs tries to
/// set `trusted.overlay.opaque`, which a user namespace cannot set, and every
/// change with the shape of a directory, such as `rm x && mkdir x`, fails
/// with EIO. Confirmed by hand on kernel 6.18.42: `userxattr` moves that
/// bookkeeping into `user.overlay.*`, a
/// namespace this process can already write.
pub fn mountOverlay(allocator: std.mem.Allocator, o: Mount.Overlay, diag: ?*?Diagnostic) MountError!void {
    const options = std.fmt.allocPrintSentinel(
        allocator,
        "lowerdir={s},upperdir={s},workdir={s},userxattr",
        .{ o.lower, o.upper, o.work },
        0,
    ) catch return error.OutOfMemory;
    defer allocator.free(options);

    const target_z = try allocator.dupeZ(u8, o.target);
    defer allocator.free(target_z);

    const rc = linux.mount("overlay", target_z, "overlay", 0, @intFromPtr(options.ptr));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        // EPERM is exactly what a kernel before 5.11 returns for an overlay
        // mount attempted from inside a user namespace: before that version
        // overlayfs did not carry FS_USERNS_MOUNT. ENODEV is what a kernel
        // with no overlayfs support built in actually returns here, confirmed
        // by hand. NOSYS is kept too, in case a future kernel ever uses it.
        .PERM, .NODEV, .NOSYS => return error.OverlayNotSupported,
        // A component of lower, upper, or work could not be read by this
        // process. The overlay filesystem itself is available; only one of
        // the paths is not.
        .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .overlay_mount, err);
            return error.Unexpected;
        },
    }
}

/// Mount one capped scratch area at `target` under `root`, and give back a
/// descriptor on it. See `Scratch` for what this is for and why a tmpfs is the
/// only mechanism available.
///
/// `size_bytes` is the cap. **Null means no cap**, which mounts an ordinary
/// tmpfs whose own default is half of the machine's memory. Only a test that
/// has to prove the cap is what stopped something asks for that, by running the
/// same program twice: see `rlimits.Limits.none`.
///
/// **Allocates nothing.** This runs in the middle process, after a `fork` that
/// may have happened while another thread of the caller held an allocator's
/// lock, so every path here is built in a stack buffer, the same rule
/// `cgroup.zig` follows and for the same reason.
///
/// **The descriptor is the whole point of giving one back.** The area only
/// exists inside this mount namespace, and the process that has to read it
/// afterwards has by then denied itself every path, so a name would not resolve
/// and a descriptor does not have to: see `scratchIsFull`. It is `CLOEXEC`, so
/// the sandboxed program never inherits it across `execve`.
pub fn mountScratch(
    root: []const u8,
    target: []const u8,
    size_bytes: ?u64,
    diag: ?*?Diagnostic,
) MountError!i32 {
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const full_len = joinInto(&full, root, target) orelse return error.Unexpected;
    try makeDirPath(full[0..full_len], diag);

    var full_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = terminate(&full_z, full[0..full_len]) orelse return error.Unexpected;

    // An empty option string is what asks the kernel for a tmpfs with its own
    // default size. `bufPrintZ` cannot fail on a 32 byte buffer holding
    // "size=" and a 64 bit number, and a refusal here would be this code's own
    // bug rather than the kernel's, so it is reported as one.
    var options_buffer: [32]u8 = undefined;
    const options: [:0]const u8 = if (size_bytes) |bytes|
        std.fmt.bufPrintZ(&options_buffer, "size={d}", .{bytes}) catch return error.Unexpected
    else
        "";

    const rc = linux.mount(
        "tmpfs",
        zeroed,
        "tmpfs",
        linux.MS.NOSUID | linux.MS.NODEV,
        @intFromPtr(options.ptr),
    );
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .scratch_mount, err);
            return error.Unexpected;
        },
    }

    const fd_rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .scratch_open, err);
            return error.Unexpected;
        },
    }
    return @intCast(fd_rc);
}

/// True when the scratch area `fd` names has no space left in it.
///
/// **This is what makes a full scratch area legible instead of confusing.** A
/// program that fills one gets `ENOSPC`, prints "No space left on device", and
/// exits. A person reading that goes and looks at their own disk and finds it
/// fine. Nothing in the kernel counts this the way `memory.events` counts an
/// out of memory kill, so the evidence has to be read from the filesystem
/// itself, and this is the only reading of it.
///
/// **It is evidence and not proof, and the caller must say so.** A program that
/// filled the area, met `ENOSPC`, deleted its own files and then failed for an
/// unrelated reason reads as not full here. The direction of that error is the
/// safe one: it never names a limit that was not reached.
///
/// The magic number is checked, so a descriptor on anything this code did not
/// mount can never be reported as one of the sandbox's own areas.
pub fn scratchIsFull(fd: i32) bool {
    var stat_buf: Statfs = undefined;
    const rc = linux.syscall2(
        .fstatfs,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(&stat_buf),
    );
    if (linux.errno(rc) != .SUCCESS) return false;
    if (stat_buf.f_type != tmpfs_magic) return false;
    return stat_buf.f_bavail == 0;
}

/// `a/b` in `buffer`, with exactly one separator between them and no
/// allocation. Null when the result does not fit. The allocation free twin of
/// what `std.fs.path.join` does for the rest of this file.
fn joinInto(buffer: []u8, a: []const u8, b: []const u8) ?usize {
    const left = if (a.len > 1 and a[a.len - 1] == '/') a[0 .. a.len - 1] else a;
    const right = if (b.len > 0 and b[0] == '/') b[1..] else b;
    const needed = left.len + 1 + right.len;
    if (needed > buffer.len) return null;
    @memcpy(buffer[0..left.len], left);
    buffer[left.len] = '/';
    @memcpy(buffer[left.len + 1 ..][0..right.len], right);
    return needed;
}

/// A null terminated copy of `text` in `buffer`, for a syscall that takes a
/// path. Null when it does not fit, which the caller reports as a refusal
/// rather than truncating: a truncated path names a different directory, and
/// this code mounts over whatever it names.
fn terminate(buffer: []u8, text: []const u8) ?[:0]const u8 {
    if (text.len + 1 > buffer.len) return null;
    @memcpy(buffer[0..text.len], text);
    buffer[text.len] = 0;
    return buffer[0..text.len :0];
}

/// `makePath` for a directory, with no allocator. See `mountScratch` for why
/// the caller cannot use one.
fn makeDirPath(path: []const u8, diag: ?*?Diagnostic) MountError!void {
    std.debug.assert(path.len > 0 and path[0] == '/');

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len + 1 > buffer.len) return error.Unexpected;
    @memcpy(buffer[0..path.len], path);

    var i: usize = 1;
    while (i <= path.len) : (i += 1) {
        if (i < path.len and path[i] != '/') continue;
        const kept = if (i < path.len) path[i] else 0;
        buffer[i] = 0;
        try makeDir(@ptrCast(&buffer), diag);
        buffer[i] = kept;
    }
}

/// Whether `source` names a directory. Used to decide whether a mount target
/// should be created as a file or a directory before the bind mount runs.
fn sourceIsDirectory(source: [*:0]const u8, diag: ?*?Diagnostic) MountError!bool {
    var stat_buf: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, source, 0, .{ .TYPE = true }, &stat_buf);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOENT => return error.SourceMissing,
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .mount_source_stat, err);
            return error.Unexpected;
        },
    }
    return (stat_buf.mode & linux.S.IFMT) == linux.S.IFDIR;
}

/// The kernel's `struct mount_attr`, the argument `mount_setattr` reads. Zig's
/// standard library does not define this type, and its `mount_setattr` wrapper
/// does not match the real five argument syscall, so this file defines the ABI
/// by hand from the kernel's `uapi/linux/mount.h`.
const MountAttr = extern struct {
    attr_set: u64 = 0,
    attr_clr: u64 = 0,
    propagation: u64 = 0,
    userns_fd: u64 = 0,
};

/// `MOUNT_ATTR_RDONLY` from `uapi/linux/mount.h`. Zig's `MOUNT_ATTR` packed
/// struct is only used by the standard library's own broken wrapper above, so a
/// call built by hand needs the raw bit again here.
const mount_attr_rdonly: u64 = 0x00000001;

/// `MOUNT_ATTR_NOSUID` from `uapi/linux/mount.h`.
const mount_attr_nosuid: u64 = 0x00000002;

/// `MOUNT_ATTR_NODEV` from `uapi/linux/mount.h`.
const mount_attr_nodev: u64 = 0x00000004;

/// Mark a mount, and everything already mounted under it, read only.
///
/// A remount can only replace the whole flag word, and the kernel locks RDONLY,
/// NODEV, NOSUID, NOEXEC, and the atime group on a mount this user namespace did
/// not create. A remount that does not repeat every locked flag is read as an
/// attempt to loosen the mount and refused with EPERM, even for a source such as
/// /sys that is merely noexec, not something we want writable. `mount_setattr`
/// takes a set of attributes to add and a set to clear instead, so a locked flag
/// already in place is never touched and never has to be guessed at.
///
/// `AT_RECURSIVE` makes the mark apply to every mount already nested under the
/// target too, such as a tmpfs mounted under a project directory before the
/// directory was marked read only. Without it, only the top mount is read only
/// and a submount underneath stays writable.
///
/// NOSUID and NODEV ride along with RDONLY in the same `attr_set`. `mount_setattr`
/// only ever adds an attribute here, never removes one, so asking for NOSUID and
/// NODEV alongside RDONLY cannot loosen anything and cannot fail on a flag the
/// kernel already locked. A sandboxed process should not be able to run a
/// set-user-ID binary or open a device node from a mount meant to be read only,
/// even if the file underneath somehow carries the set-user-ID bit or is a device
/// special file.
fn markReadOnly(target: [*:0]const u8, diag: ?*?Diagnostic) MountError!void {
    var attr = MountAttr{
        .attr_set = mount_attr_rdonly | mount_attr_nosuid | mount_attr_nodev,
    };
    const rc = linux.syscall5(
        .mount_setattr,
        @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
        @intFromPtr(target),
        @as(usize, linux.AT.RECURSIVE),
        @intFromPtr(&attr),
        @sizeOf(MountAttr),
    );
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        // mount_setattr does not exist before kernel 5.12. Name this specifically,
        // so a user on an old kernel is told what is missing instead of being
        // handed the same Unexpected a real bug would produce.
        .NOSYS => return error.KernelTooOld,
        else => |err| {
            note(diag, .mount_setattr, err);
            return error.Unexpected;
        },
    }
}

// Zig 0.16 moved directory creation behind std.Io.Dir, which needs an Io instance
// this file does not carry, so a mount target is created the same way every other
// path in this file reaches the kernel: through linux.mkdirat and linux.open
// directly.
//
// `path` must be absolute. Every caller in this file builds `path` by joining onto
// `root`, which is always absolute, so a relative path here is our own bug.
//
// `kind` decides what the last path component becomes. Every component before it
// is always a directory, because it is only ever a parent of the real target.
fn makePath(allocator: std.mem.Allocator, path: []const u8, kind: PathKind, diag: ?*?Diagnostic) MountError!void {
    std.debug.assert(path.len > 0 and path[0] == '/');

    var i: usize = 1;
    while (i <= path.len) : (i += 1) {
        if (i < path.len and path[i] != '/') continue;

        const prefix = try allocator.dupeZ(u8, path[0..i]);
        defer allocator.free(prefix);

        const is_leaf = i == path.len;
        if (is_leaf and kind == .file) {
            try makeFile(prefix.ptr, diag);
        } else {
            try makeDir(prefix.ptr, diag);
        }
    }
}

fn makeDir(path: [*:0]const u8, diag: ?*?Diagnostic) MountError!void {
    switch (linux.errno(linux.mkdirat(linux.AT.FDCWD, path, 0o755))) {
        // EXIST is not a failure here. mkdir -p tolerates an existing directory at
        // each step, and that is exactly what this loop hits on every path segment
        // that a previous mount, or a previous run, already created.
        .SUCCESS, .EXIST => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .mount_target_mkdir, err);
            return error.Unexpected;
        },
    }
}

fn makeFile(path: [*:0]const u8, diag: ?*?Diagnostic) MountError!void {
    // No O_EXCL, so an existing file at this path is left alone and simply
    // opened. Its content does not matter, the bind mount is about to cover it.
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .mount_target_open, err);
            return error.Unexpected;
        },
    }
    _ = linux.close(@intCast(fd_rc));
}

fn mountCall(
    source: ?[*:0]const u8,
    target: [*:0]const u8,
    fstype: ?[*:0]const u8,
    flags: u32,
    data: usize,
    diag: ?*?Diagnostic,
) MountError!void {
    const rc = linux.mount(source, target, fstype, flags, data);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            // Every other errno above already tells the caller what to do. This
            // one does not, so the errno is the only fact left that can point at
            // the real cause, and folding it into Unexpected without printing it
            // would throw that fact away right where it matters most.
            note(diag, .mount_call, err);
            return error.Unexpected;
        },
    }
}

/// Move the process into the new root and remove the old one.
///
/// After this call, no path resolves to anything on the host: open() on a host
/// path fails, because the host tree is no longer anywhere in this process's
/// mount namespace. That is not the same claim as "the host is unreachable". A
/// file descriptor opened before `enter` keeps working after this call, because
/// a descriptor does not go through path resolution again once it is open, and
/// a directory descriptor can still be used with openat to reach the host tree
/// by name. A caller that wants the "cannot reach the host" property to actually
/// hold must close every descriptor opened before `enter`, before it lets the
/// sandboxed process run. This function does not close them: that decision
/// belongs to whichever function started the process, not to the one building
/// its mount tree.
pub fn pivotInto(allocator: std.mem.Allocator, root: []const u8, diag: ?*?Diagnostic) MountError!void {
    const old = try std.fs.path.join(allocator, &.{ root, ".old_root" });
    defer allocator.free(old);
    try makePath(allocator, old, .directory, diag);

    const root_z = try allocator.dupeZ(u8, root);
    defer allocator.free(root_z);
    const old_z = try allocator.dupeZ(u8, old);
    defer allocator.free(old_z);

    switch (linux.errno(linux.pivot_root(root_z, old_z))) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .pivot_root, err);
            return error.Unexpected;
        },
    }

    switch (linux.errno(linux.chdir("/"))) {
        .SUCCESS => {},
        else => |err| {
            note(diag, .chdir_after_pivot, err);
            return error.Unexpected;
        },
    }

    // Detach the old root. Without this the process keeps a path to every host file.
    // MNT_DETACH removes it from the tree even while something still uses it.
    const mnt_detach: u32 = 2;
    switch (linux.errno(linux.umount2("/.old_root", mnt_detach))) {
        .SUCCESS => {},
        else => |err| {
            note(diag, .old_root_umount, err);
            return error.Unexpected;
        },
    }

    // Best effort only. The mount point is already gone; failing to remove the now
    // empty directory does not leave any path back to the host.
    _ = linux.rmdir("/.old_root");
}
