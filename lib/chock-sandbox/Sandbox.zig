//! The public interface of chock-sandbox: one driver per way of sandboxing,
//! chosen at compile time from `builtin.os.tag`. There is no platform branch
//! inside the sandbox: there is a driver interface, and one driver per way of
//! sandboxing. `spawn` puts a driver's layers in place and runs the program; a
//! caller reads only this file's own declarations and can never learn, from a
//! type or a field here, which driver actually ran. See the "same public
//! shape" test at the bottom of this file for how that claim is checked.
//!
//! The Linux driver is `linux/driver.zig`, moved from this file unchanged:
//! it has survived three attack reviews that each found host code execution
//! or a sandbox escape, so this split kept its logic untouched and only
//! relocated the type declarations every driver shares, `Config`,
//! `SetupError`, `SpawnError`, and `LandlockReport`, to this file. The
//! Darwin driver is `darwin/driver.zig`, new in this milestone: it refuses
//! before it does anything, because a driver that returned success here
//! would hand an agent the user's whole filesystem on a platform that
//! claims to be sandboxed.
//!
//! `Config` still names `landlock.AccessFs`, `namespace.Mount`, `namespace.Network`,
//! and `seccomp.Options`, all Linux mechanisms, unchanged from before the
//! split. Redesigning `Config` into something every future driver can
//! interpret on its own terms is not this milestone's job; only the Linux
//! driver reads these fields today, and the Darwin driver below refuses
//! before it ever would. `Guarantee` and `Guarantees`, also below, are the
//! part of this file that answers the next question: a driver names which
//! guarantees it actually gives, so that a later milestone can compare a
//! policy against a driver and refuse when the driver is short.

const std = @import("std");
const builtin = @import("builtin");
const landlock = @import("linux/landlock.zig");
const namespace = @import("linux/namespace.zig");
const seccomp = @import("linux/seccomp.zig");
const rlimits = @import("linux/rlimits.zig");
const cgroup = @import("linux/cgroup.zig");

/// `landlock.zig`, `namespace.zig`, and `seccomp.zig` are Linux-only
/// mechanisms, and every line in them that reaches the kernel says so with
/// a raw syscall from the Linux namespace of Zig's standard library.
/// Importing their names here, in a file with no `linux` directory
/// component of its own, does not: this file only ever names a *type* they
/// declare, for `Config` below, the same way a driver that cannot apply a
/// layer is still allowed to know what the layer is called. See
/// `tools/lint_linux_only.zig`'s own top comment for the exact rule this
/// file is written to satisfy.
/// The one directory inside a sandbox root that belongs to Chock, and not to
/// the project the root stands for.
///
/// **The root is the project's.** Everything Chock has to place inside a
/// sandbox for its own sake, the redirected git directory, the session's
/// scratch object store, and the one executable a tool call runs, goes under
/// this, so the project's own paths keep the root to themselves and the
/// filesystem conventions for runtime state are kept.
///
/// One parent instead of several siblings is also one thing to control when
/// deciding what the agent may reach. Named here, in the library that owns
/// what a sandbox root looks like, so `chock-workspace` and `chock-core`
/// share one spelling: neither imports the other, and a second spelling is
/// how two paths quietly stop agreeing.
///
/// **Nothing mounts this path itself.** `namespace.makePath` creates it, and
/// `/run` above it, as ordinary directories before the first mount under it,
/// and tolerates ones that already exist. A mount *at* this path, or at
/// `/run`, would shadow everything under it, because the kernel takes the
/// last matching mount and not the longest prefix: see
/// `lib/chock-workspace/worktree.zig`'s own test for that.
pub const runtime_prefix = "/run/chock";

/// What this build's driver can express in a `Config`.
///
/// **These are the questions `darwin/driver.zig`'s own `Inexpressible` answers
/// at run time, asked here at compile time by the callers that would otherwise
/// build a config that driver refuses.** A caller that asks for one of these on
/// a build that has it gets exactly what it always did; a caller that asks on a
/// build that has none gets the whole tool call refused, which is what a
/// session on macOS measured before these existed. Read from the target, the
/// same way `driver` below is chosen, because the two must agree.
///
/// macOS is the platform that answers false, and it stays that way.
/// `lib/chock-workspace/layout.zig` is the same decision for the workspace.
pub const expresses = struct {
    /// A mount whose target is not its source. Everything Chock places under
    /// `runtime_prefix` needs one. A build that answers false leaves every path
    /// where it really is: see `lib/chock-core/cache.zig`, `scratchpad.zig`,
    /// `tasks.zig` and `tools.zig`, which each ask before they name a target.
    pub const moved_paths = builtin.os.tag != .macos;

    /// A writable area with a hard cap on how much it holds. A cap needs a
    /// filesystem this process can mount, and an ordinary user on macOS cannot
    /// mount one at all. `chock doctor` reports the same fact as its
    /// `disk cap tmpfs` row, so the limit reads `unsupported` to a person
    /// rather than reading as one that holds.
    pub const scratch_area = builtin.os.tag == .linux;

    /// A procfs of the sandbox's own. A tool call carries one so that a
    /// compiler can read `/proc/self/exe` and find its own installation. macOS
    /// has no procfs at all, on the host or anywhere else, so a program there
    /// never looks for one and a build with none takes nothing away.
    pub const procfs = builtin.os.tag == .linux;
};

/// The path a mount source or a Landlock rule must name for `path` on this
/// build. `buffer` holds the answer when one had to be resolved, so it must
/// live as long as the result.
///
/// **A driver that moves no path turns a mount into a rule, and a rule matches
/// the path the kernel resolved.** macOS reaches `$TMPDIR` below `/var`, which
/// is a link to `/private/var`, so a rule written on the unresolved spelling
/// matches nothing at all and the whole call reads as a sandbox that denies
/// every access. `src/doctor.zig`'s own probe moved off `/tmp` for that exact
/// reason, measured on 2026-08-25. A build that remaps needs none of this: the
/// kernel resolves a bind source itself.
///
/// `path` must name a directory. A caller that wants the answer for a file
/// resolves the directory it is in and joins the name back on, because a file
/// that is not there yet cannot be resolved at all.
pub fn resolvedPath(io: std.Io, path: []const u8, buffer: []u8) []const u8 {
    if (expresses.moved_paths) return path;
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch return path;
    defer dir.close(io);
    const length = dir.realPath(io, buffer) catch return path;
    return buffer[0..length];
}

pub const Config = struct {
    /// The directory that becomes the root of the sandbox.
    root: []const u8,
    /// The mounts to make inside the root: a bind mount, an overlay mount, a
    /// procfs of the sandbox's own, or a denied path, per entry. See
    /// `linux/namespace.zig`'s own `Mount`.
    ///
    /// **A `Mount.deny` entry is applied last whatever its place here**, so a
    /// caller cannot lose a denial by putting it before the mount that would
    /// cover it. See `linux/namespace.zig`'s own `applyDenyMounts`.
    mounts: []const namespace.Mount,
    /// The paths that Landlock permits, and the access for each one. A path here
    /// is read after the mount tree is built, so it must name a path inside the
    /// new root, the same as a mount target above, not a path on the host.
    rules: []const Rule,
    /// The working directory inside the sandbox.
    cwd: []const u8,
    /// The environment for the program.
    env: []const []const u8,
    seccomp_options: seccomp.Options = .{},
    /// How the sandboxed process reaches the network. See `linux/namespace.zig`'s
    /// own `Network`. Defaults to `.none`, so a caller that omits this
    /// field gets no network, not the host's.
    network: namespace.Network = .none,
    /// The descriptor the sandboxed program's own standard output is
    /// duplicated onto, in the Linux driver's own `execute`, right before
    /// `execve`. Defaults to this process's own standard output, so a
    /// caller that never sets this gets the behaviour `spawn` always had:
    /// the sandboxed program's output lands wherever this process's own
    /// already does, with no descriptor juggling in this process at all.
    ///
    /// A caller that wants the sandboxed program's output somewhere else,
    /// such as a pipe read while the program still runs, names that
    /// descriptor here instead: see `lib/chock-core/tools.zig`'s own
    /// `spawnCapturing`. See `linux/driver.zig`'s own doc comment on this
    /// same field for the full reasoning; it carries over unchanged.
    stdout_fd: std.posix.fd_t = std.posix.STDOUT_FILENO,
    /// Same as `stdout_fd`, for the sandboxed program's own standard error.
    /// May equal `stdout_fd`: the ordinary case of a caller that wants both
    /// streams combined on one descriptor.
    ///
    /// **This one also governs a sandbox that never came up.** Every setup
    /// step, from the first one after the fork to `execve` itself, writes the
    /// reason it could not go on here, so a caller that asked for a quiet
    /// failure gets one: point this at `/dev/null` and a sandbox that cannot
    /// be built says nothing on the terminal, while `spawn` still answers with
    /// the error that names the step, such as `error.MountTreeFailed`. It used
    /// to be obeyed only from `execve` onwards, so a failure before that point
    /// reached the caller's own terminal whatever this field said. See
    /// `linux/driver.zig`'s own `writeStderr`.
    stderr_fd: std.posix.fd_t = std.posix.STDERR_FILENO,
    /// The descriptor the sandboxed program's own standard input is
    /// duplicated onto, or null for `/dev/null`.
    ///
    /// **Null is what every tool call gets, and that is the whole point of
    /// the default.** `lib/chock-core/tools.zig` names no descriptor here, so
    /// a program the model asked for reads end of file from `/dev/null` on
    /// descriptor 0: a password prompt then fails fast instead of waiting on
    /// input nobody will write, and there is no route from descriptor 0 to
    /// the caller's own terminal. See `linux/driver.zig`'s own
    /// `redirectStdinToDevNull` for both reasons in full.
    ///
    /// A caller names a descriptor here only for a **helper the harness
    /// itself starts**: a long lived program, chosen by Chock and never by
    /// the model, that answers on a pipe. See `lib/chock-core/helper.zig`,
    /// which is the only caller in this project that fills this field in.
    ///
    /// **What a real pipe on descriptor 0 gives the sandboxed program, and
    /// why none of it is a way out:**
    ///
    /// * **Bytes the harness wrote, and nothing else.** A pipe carries only
    ///   what the process on the other end put in it. The harness is that
    ///   process, so the whole content of descriptor 0 is a message Chock
    ///   composed.
    /// * **No path, so no reach.** A pipe has no name in any filesystem.
    ///   `openat` on it is meaningless, and it cannot be walked back to the
    ///   host tree the way an inherited directory descriptor could. That is
    ///   the property `closeInheritedFds` exists to enforce for every *other*
    ///   descriptor, and it still closes every other descriptor: this one is
    ///   an exception of exactly one number.
    /// * **No terminal, so no `TIOCSTI`.** The injection route
    ///   `redirectStdinToDevNull` closes needs descriptor 0 to be the
    ///   caller's controlling terminal. A pipe is not a terminal, and the
    ///   kernel answers `ENOTTY` to every terminal `ioctl` on one.
    /// * **A write back is a write to the harness, which reads it as data.**
    ///   The harness never treats what a helper says as an instruction: see
    ///   `lib/chock-core/lsp.zig`, which puts a server's own words in front
    ///   of the model as text and lets nothing it says reach a decision.
    ///
    /// The one thing it really does add is that the program can now **block**
    /// on a read of descriptor 0, which `/dev/null` made impossible. That is
    /// the caller's problem and not the sandbox's: a helper's owner holds a
    /// budget on every exchange, and a helper that never answers is dropped.
    ///
    /// `/dev/null` still goes on descriptor 0 first, before any layer, on
    /// every call including this one. The descriptor named here replaces it
    /// in the last step before `execve`, so nothing in the setup path can
    /// read a caller's pipe, and a program whose sandbox failed to come up
    /// never sees one byte of it.
    stdin_fd: ?std.posix.fd_t = null,
    /// How much of the machine this program may consume: memory, processes,
    /// open descriptors, the size of one file, and cpu time.
    ///
    /// **Every other layer of this sandbox is about reach. This one is about
    /// appetite.** A fork bomb, an allocation that never stops, and a
    /// descriptor leak all pass the namespaces, Landlock and seccomp without
    /// touching any of them. See `linux/rlimits.zig`'s own top comment for
    /// each limit and the reason for it, including the ones this project
    /// decided not to set, and `linux/cgroup.zig` for the half of the answer
    /// that needs a cgroup v2 tree.
    ///
    /// The default bounds every one of the five. A caller that really wants
    /// an unbounded program says so with `Limits.none`, and only a test has a
    /// reason to.
    ///
    /// The Darwin driver reads this field and applies nothing, the same as
    /// every other field on this struct: it refuses before it reaches a
    /// layer at all. See `darwin/driver.zig`.
    limits: Limits = .{},
    /// The writable areas the sandbox owns, each one a tmpfs of its own with a
    /// hard cap on how much it can hold. Empty by default, so a caller that
    /// names none gets none.
    ///
    /// **This is the only capacity limit an unprivileged process can put on a
    /// filesystem**, and it is the one row of `linux/rlimits.zig`'s own table
    /// that no rlimit and no cgroup covers: `RLIMIT_FSIZE` bounds one file, and
    /// ten thousand files of one byte each still fill a disk. See
    /// `linux/namespace.zig`'s own `Scratch` for the measurements and the mount
    /// options, and `linux/rlimits.zig`'s own `default_scratch_bytes` for which
    /// areas should be named here, which one deliberately should not, and why
    /// the cap and the memory ceiling are one decision rather than two.
    ///
    /// Every area named here gets `Limits.scratch_bytes` as its cap. One number
    /// for every area, so a caller cannot give one area a cap that makes the
    /// memory ceiling unreachable while another looks fine.
    ///
    /// **A path here is a path inside the sandbox**, the same as a mount target
    /// and the same as a Landlock rule, and it is created if it is not already
    /// there. An area a Landlock rule does not also permit is an area the
    /// program cannot write, so a caller names it in both places.
    ///
    /// The Darwin driver reads this field and applies nothing, the same as
    /// every other field on this struct: it refuses before it reaches a layer
    /// at all.
    scratch: []const namespace.Scratch = &.{},
    /// Who answers a filtered process's request for a connection.
    ///
    /// **Required when `network` is `.filtered`, and refused otherwise.**
    /// `spawn` answers `error.NetBrokerMissing` for a filtered config with no
    /// broker, rather than quietly giving that process a `.none` sandbox: a
    /// caller that asked for a channel out and silently got none would spend
    /// its turns on a failure that names nothing. It answers
    /// `error.NetBrokerNotFiltered` for a broker on a config that is not
    /// filtered, because that config has no socket to serve and the field
    /// would read as a permission that is never used.
    ///
    /// The Darwin driver reads this field and applies nothing, the same as
    /// every other field on this struct: it refuses before it reaches a layer
    /// at all.
    ///
    /// **`Config.copy` carries this across as it is**, the same as
    /// `limits_report` and the three descriptor fields, because it points at
    /// the caller's own storage.
    net_broker: ?NetBroker = null,
    /// Filled in with what the limits layer actually did, when a caller wants
    /// to know. Null is the ordinary case.
    ///
    /// **A limit that stopped a program has to be legible**, and a signal
    /// number is not. `memory.max` kills with a bare `SIGKILL`, which reads
    /// exactly like the `SIGTERM`/`SIGKILL` a cancelled call gets, so a
    /// caller that only saw the `Term` could not tell a tool call that ran
    /// out of memory from one a person stopped. This is how it learns which
    /// it was, and which mechanism carried each bound. See `LimitsReport`.
    ///
    /// A caller that leaves this null still gets the fact: the Linux driver
    /// writes one line naming the limit to its own standard error, the same
    /// way it reports a layer the middle process could not put on.
    ///
    /// **`Config.copy` carries this pointer across as it is**, the same as
    /// the three descriptor fields, because it points at the caller's own
    /// storage and duplicating it would report into a copy nobody reads. So a
    /// config that outlives the storage this names, which is what `copy`
    /// exists for, must name storage that outlives it too, or leave this
    /// null.
    limits_report: ?*LimitsReport = null,

    pub const Rule = struct {
        path: []const u8,
        access: landlock.AccessFs,
    };

    /// A copy of this config in `allocator`, sharing no memory with the
    /// original.
    ///
    /// **For a caller that outlives the arena the config was built in.** The
    /// config a tool call holds borrows its mounts, its rules and its
    /// environment from an arena that is freed the moment that call returns,
    /// and both `chock_core.tasks.Table` and `chock_core.helper.Helper`
    /// outlive one call by definition. A caller that read the borrowed slices
    /// would be reading freed memory on the first turn that ended before it
    /// did.
    ///
    /// **Nothing is freed one piece at a time.** Give an arena, and drop the
    /// whole arena when the copy is finished with.
    ///
    /// The three descriptor fields are carried across as they are: a
    /// descriptor is a number in this process, not memory to duplicate. So
    /// are `limits`, which is five numbers and owns no memory, and
    /// `limits_report`, which points at a caller's own storage that this
    /// function has no business duplicating.
    ///
    /// It lives here, in the library that owns the type, because a second
    /// spelling of this function is how two copies quietly stop agreeing when
    /// a field is added. A field added below is copied by this function on the
    /// day it is added, or it is not copied by any caller at all.
    pub fn copy(self: Config, allocator: std.mem.Allocator) std.mem.Allocator.Error!Config {
        var out = self;
        out.root = try allocator.dupe(u8, self.root);
        out.cwd = try allocator.dupe(u8, self.cwd);
        out.env = try copyStrings(allocator, self.env);

        const mounts = try allocator.alloc(namespace.Mount, self.mounts.len);
        for (self.mounts, mounts) |from, *to| {
            to.* = switch (from) {
                .bind => |bind| .{ .bind = .{
                    .source = try allocator.dupe(u8, bind.source),
                    .target = try allocator.dupe(u8, bind.target),
                    .read_only = bind.read_only,
                } },
                .overlay => |overlay| .{ .overlay = .{
                    .lower = try allocator.dupe(u8, overlay.lower),
                    .upper = try allocator.dupe(u8, overlay.upper),
                    .work = try allocator.dupe(u8, overlay.work),
                    .target = try allocator.dupe(u8, overlay.target),
                } },
                .proc => |proc| .{ .proc = .{ .target = try allocator.dupe(u8, proc.target) } },
                .deny => |deny| .{ .deny = .{ .target = try allocator.dupe(u8, deny.target) } },
            };
        }
        out.mounts = mounts;

        const rules = try allocator.alloc(Rule, self.rules.len);
        for (self.rules, rules) |from, *to| {
            to.* = .{ .path = try allocator.dupe(u8, from.path), .access = from.access };
        }
        out.rules = rules;

        const scratch = try allocator.alloc(namespace.Scratch, self.scratch.len);
        for (self.scratch, scratch) |from, *to| {
            to.* = .{ .target = try allocator.dupe(u8, from.target) };
        }
        out.scratch = scratch;
        return out;
    }
};

/// A copy of every string in `from`, in `allocator`. Used by `Config.copy` and
/// by callers that copy an argv beside a config.
pub fn copyStrings(
    allocator: std.mem.Allocator,
    from: []const []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    const to = try allocator.alloc([]const u8, from.len);
    for (from, to) |one, *slot| slot.* = try allocator.dupe(u8, one);
    return to;
}

/// Who answers a filtered process's request for a connection, and the one seam
/// this library has for it. See `Config.net_broker`, and
/// `linux/netbroker.zig` for the exchange that reaches this.
///
/// ## Why the decision is not in here
///
/// **A host policy is not the sandbox's to hold.** `chock-sandbox` imports no
/// other chock library, so it cannot read
/// `chock.zon` and must never grow a second, private answer to "may this run
/// reach that host". What it owns is the boundary: the request arrives as
/// bytes from a process that is assumed hostile, this library bounds and
/// checks the shape of those bytes, and then it asks. What comes back is a
/// descriptor or a refusal.
///
/// **The connect happens on this side of the boundary**, in the process that
/// implements this interface, so a sandboxed process cannot reach a host
/// merely by knowing its address. See `lib/chock-broker/network.zig`, which is
/// the real implementation, and which also decides what a name is allowed to
/// be and when it is resolved.
///
/// ## What a granted descriptor is worth, and for how long
///
/// **It outlives the check, and that is accepted.** Once the descriptor
/// crosses, the sandboxed process holds a connection for as long as it keeps
/// the descriptor open, and nothing revokes it. Three facts make that bounded
/// rather than open ended:
///
/// * **It names one connection and cannot be aimed at another.** A connected
///   TCP socket really can be re-aimed with `connect`, measured on 2026-08-23,
///   so the Linux driver refuses `connect` outright for a filtered process:
///   see `linux/seccomp.zig`'s own `Options.block_connect`.
/// * **The answer could not have changed anyway.** The policy table is read
///   one time and cannot change while a session runs,
///   so a check made again later would give the same answer it gave here.
/// * **It ends with the call.** The descriptor lives in a process the sandbox
///   ends: nothing in a tool call outlives that call.
pub const NetBroker = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// What one request is answered with.
    pub const Grant = union(enum) {
        /// A connected descriptor, which the driver sends across and then
        /// closes its own copy of. **The implementation gives up ownership**:
        /// after this is returned the driver closes it whether the send
        /// worked or not.
        granted: std.posix.fd_t,
        /// No connection, and no reason. **The reason never crosses the
        /// boundary**: a process that learns why it was refused learns which
        /// hosts exist, which rule shape refused it, and whether a name
        /// resolves, and it learns all of that for free by asking. The
        /// implementation keeps the reason for the person reading the session.
        refused,
    };

    pub const VTable = struct {
        /// Answer one request. `host` is a name the sandboxed process chose:
        /// the driver has already bounded its length and refused a byte that
        /// cannot be in a host name, and the implementation checks it again
        /// against its own rules. `host` borrows the driver's own buffer and
        /// is not valid after this call returns.
        connect: *const fn (ptr: *anyopaque, host: []const u8, port: u16) Grant,
    };

    pub fn connect(self: NetBroker, host: []const u8, port: u16) Grant {
        return self.vtable.connect(self.ptr, host, port);
    }
};

/// How much of the machine one sandboxed program may consume. See
/// `linux/rlimits.zig`, which owns the type and every default in it.
pub const Limits = rlimits.Limits;

/// What the resource limits layer did for one `spawn` call, and what it
/// could not do.
///
/// **This exists because a limit that kills has to be legible.** This
/// project's most repeated lesson is that a confusing failure costs turns and
/// a plain refusal costs one, and a resource limit is unusually good at
/// producing the confusing kind: `memory.max` kills with a bare `SIGKILL`,
/// which is the same thing a caller sees when a person cancels a call or when
/// the harness enforces its deadline.
///
/// It is also the capability record. A machine with no cgroup v2 tree, a
/// machine with cgroup v1, and a machine that delegates nothing are three
/// different situations, and every one of them still gets the rlimit floor.
/// `cgroup` names which of them happened rather than leaving a person to
/// believe in a bound that is not there.
pub const LimitsReport = struct {
    /// The numbers that were asked for.
    limits: Limits = .{},
    /// Whether the cgroup half went on, and why not when it did not.
    cgroup: cgroup.Support = .off,
    /// Whether `RLIMIT_NPROC` went on. False on a kernel older than 5.14,
    /// where it counts the user's own processes on the host rather than the
    /// sandbox's own. See `rlimits.nproc_per_user_namespace_since`, which
    /// holds the measurement this is based on.
    nproc_applied: bool = false,
    /// What the kernel counted inside the cgroup while the program ran. All
    /// zero when there was no cgroup, which reads the same as "no cgroup
    /// limit was reached" and is the truth in that case.
    events: cgroup.Events = .{},
    /// True when a scratch area had no space left in it when the program
    /// ended. Read from the filesystem itself, because nothing in the kernel
    /// counts this the way `memory.events` counts an out of memory kill: see
    /// `linux/namespace.zig`'s own `scratchIsFull`.
    ///
    /// **Reported whatever the program's outcome was.** A program that filled
    /// an area and then exited 0 did not fail, and a caller that wants to warn
    /// about it can, while `killed_by` below stays honest about what ended the
    /// program.
    scratch_full: bool = false,
    /// The limit that ended the program, when one did. Null when the program
    /// ended for any other reason, including a cancel and an ordinary exit.
    ///
    /// **`scratch_space` is the one member here that is inferred and not
    /// counted.** Every other one comes from a signal number or a kernel
    /// counter. A full scratch area is neither: the kernel answers the program
    /// with `ENOSPC` and keeps no record, so this reads "the area was full when
    /// the program ended badly" as "the area is what ended it". That can be
    /// wrong, and it errs in the safe direction: an area that is not full is
    /// never named. See `scratch_full`, which is the raw fact with no inference
    /// in it at all.
    killed_by: ?rlimits.Diagnostic.Which = null,

    /// One sentence for a person, or null when no limit ended the program.
    /// Written into `buffer`, so this allocates nothing and can be called
    /// from the same places `spawn` itself can.
    pub fn killedText(self: LimitsReport, buffer: []u8) ?[]const u8 {
        const which = self.killed_by orelse return null;

        // **A scratch area is not a disk, and the sentence has to say so.**
        // A program that fills one prints "No space left on device", and a
        // person who reads only that goes and looks at their own filesystem,
        // finds it fine, and has lost a turn. This project's most repeated
        // lesson is that a confusing failure costs turns and a plain refusal
        // costs one, so the refusal names the area, names the cap, and says
        // outright that the machine's own disk is not the thing that filled.
        if (which == .scratch_space) {
            if (self.limits.scratch_bytes) |number| {
                return std.fmt.bufPrint(
                    buffer,
                    "the program filled the sandbox's own scratch area, which chock caps at {d} bytes. The machine's own disk is not full",
                    .{number},
                ) catch null;
            }
            return std.fmt.bufPrint(
                buffer,
                "the program filled the sandbox's own scratch area. The machine's own disk is not full",
                .{},
            ) catch null;
        }

        const value: ?u64 = switch (which) {
            .memory => self.limits.memory_bytes,
            .mapped_memory => self.limits.mapped_memory_bytes,
            .cpu_time => self.limits.cpu_seconds,
            .file_size => self.limits.file_size_bytes,
            .processes => self.limits.processes,
            .open_files => self.limits.open_files,
            .core_dump, .scratch_space => null,
        };
        const unit: []const u8 = switch (which) {
            .memory, .mapped_memory, .file_size => " bytes",
            .cpu_time => " seconds",
            else => "",
        };
        if (value) |number| {
            return std.fmt.bufPrint(
                buffer,
                "the program was stopped by the limit on {s}, which is {d}{s}",
                .{ which.text(), number, unit },
            ) catch null;
        }
        return std.fmt.bufPrint(
            buffer,
            "the program was stopped by the limit on {s}",
            .{which.text()},
        ) catch null;
    }
};

/// The guarantees a driver can give. A driver declares which guarantees it
/// gives, Chock compares the policy against the driver, and refuses when the
/// driver is short. Nothing compares against this set yet, and only two
/// drivers exist, but the shape has to exist before that comparison can, and
/// before a third driver, such as a Darwin virtual machine, has something to
/// declare against.
pub const Guarantee = enum {
    /// No network route out of the sandbox. Linux: network namespace.
    /// Darwin design: `(deny network*)`.
    ///
    /// **This is a statement about the driver and not about one call.** A
    /// driver that gives it takes a network namespace for `Config.network` of
    /// `.none` and of `.filtered` alike, so a filtered process still has
    /// no route of its own. What a filtered process has in addition is one
    /// descriptor on a socket pair, and what comes back over it is a
    /// connection a policy permitted: see `NetBroker`. A `.host` config gives
    /// this up altogether, which is why the Linux driver refuses `.host` for
    /// everything except an act the user approved.
    network_isolated,
    /// Every other process is hidden, and cannot receive a signal from
    /// inside. Linux: a PID namespace **and a process group of the
    /// sandbox's own**. Darwin design: `(deny signal)`.
    ///
    /// **The PID namespace alone does not give this.** A namespace hides a
    /// process by number, and `kill(0, sig)` names no number: it names the
    /// caller's own process group, which the kernel holds as an object and
    /// not as an identifier. Measured on 2026-08-21: a process in a fresh
    /// PID namespace reads `getpgid(0)` as 0, because its group has no
    /// number in that namespace, and `kill(0, sig)` from there still
    /// reached a process outside the namespace, in the group the sandbox
    /// inherited from its caller. So the Linux driver puts the sandbox in a
    /// process group of its own; see that driver's own `newProcessGroup`.
    signal_isolated,
    /// System V shared memory and message queues do not cross the boundary.
    /// Linux: IPC namespace. Darwin design: `(deny ipc-posix-shm)`.
    ipc_isolated,
    /// Read and write access is limited to named paths. Linux: Landlock.
    /// Darwin design: `file-read*` and `file-write*` rules.
    path_restricted,
    /// A denylist of dangerous system calls is enforced. Linux: seccomp-bpf.
    /// Darwin design: `(deny syscall-unix ...)`, narrower than seccomp but real.
    syscall_restricted,
    /// The workspace appears at the real project path, and the real project
    /// tree is not otherwise reachable from inside the sandbox. Linux:
    /// mount namespace and bind mounts. Darwin: none, and that gap is
    /// permanent, not one a future Seatbelt profile closes. macOS has no bind
    /// mount, and there are only bad answers to this.
    workspace_mounted,
};

pub const Guarantees = std.EnumSet(Guarantee);

/// What a setup step can fail with, named one member per the Linux driver's
/// own `SetupStep`, so a caller can match on exactly which layer never came
/// up. Declared here, not on the Linux driver, so every driver's own
/// `SpawnError` can carry the same shape without importing another
/// driver's file. Only the Linux driver returns one of these today; the
/// Darwin driver refuses through `SpawnError.NoMountNamespace` below before
/// it reaches anything resembling one of these steps.
pub const SetupError = error{
    StdinRedirectFailed,
    ProcessGroupFailed,
    /// The process could not be moved into the cgroup that carries its
    /// resource limits. Reported rather than ignored: a program that ran on
    /// outside its cgroup would have no memory bound and no process bound at
    /// all, and nothing later in the setup would notice.
    CgroupJoinFailed,
    /// A resource limit could not be put on the process. See
    /// `linux/rlimits.zig`.
    ResourceLimitFailed,
    CloseFdsFailed,
    NamespaceFailed,
    /// A capped scratch area could not be mounted. Reported rather than
    /// ignored: a program that ran on with an ordinary directory where a capped
    /// area was asked for has no bound on what it writes, and nothing later in
    /// the setup would notice. See `Config.scratch`.
    ScratchMountFailed,
    MountTreeFailed,
    PivotFailed,
    LandlockInitFailed,
    LandlockRuleFailed,
    LandlockRestrictFailed,
    SessionKeyringFailed,
    SeccompInstallFailed,
    ForkFailed,
    PdeathsigSetupFailed,
    ExecFailed,
};

pub const SpawnError = error{
    /// The kernel has no Landlock. Report this. Do not continue without the layer.
    LandlockUnavailable,
    /// The setup pipe carried data that cannot be trusted as a real setup
    /// failure record: the wrong number of bytes, more than one record's
    /// worth, a bad magic value, or a step byte that names no known step.
    /// Only the Linux driver's own pipe protocol can produce this.
    UntrustedSetupReport,
    /// `fork`, `waitpid`, `pidfd_open`, or a read of the setup pipe returned
    /// an errno with no specific recovery. The `pidfd_open` case is the one
    /// that refuses rather than degrades: a caller that asked for a `Middle`
    /// and got no handle would have a call it cannot cancel, so `spawn` ends
    /// the process it just forked and reports this instead.
    Unexpected,
    /// A driver that cannot give the guarantees `spawn` promises refuses
    /// before it runs anything, named for the layer it cannot apply. Chock
    /// refuses to run before it runs without a sandbox. Only the Darwin driver
    /// returns this today, and it returns it for a config that needs a mount
    /// tree, which is the one layer that platform has not got. A config whose
    /// every path stays where it is runs there: see `darwin/driver.zig`'s
    /// `Inexpressible` for the whole rule.
    NoMountNamespace,
    /// `Config.network` is `.filtered` and `Config.net_broker` is null, so
    /// there is nobody for the sandboxed process to ask. **Refused rather
    /// than downgraded to `.none`**: see `Config.net_broker`.
    NetBrokerMissing,
    /// `Config.net_broker` is set on a config whose `network` is not
    /// `.filtered`. There is no socket to serve, so the broker would never be
    /// asked anything, and a field that reads as a permission and grants none
    /// is worse than a refusal.
    NetBrokerNotFiltered,
    /// The socket pair that carries the requests could not be made.
    NetBrokerSocketFailed,
} || SetupError || std.mem.Allocator.Error;

/// What `spawn` learned about the Landlock layer while it built the sandbox.
/// Chock never degrades quietly: the Linux driver's own Landlock ruleset
/// masks a right out of the whole ruleset when the running kernel's ABI
/// does not have it, and says nothing on its own. This is how `spawn` hands
/// that fact back, so the caller can compare `abi` against the version the
/// design expects and tell the user when the kernel forced a smaller
/// ruleset than they asked for. The Darwin driver never fills this in: it
/// refuses before it would ever probe a Landlock ABI.
pub const LandlockReport = struct {
    /// The kernel's Landlock ABI version, from the Linux driver's own
    /// `landlock.probeAbi`.
    abi: i32,
    /// The rights that ABI version actually has. A right this struct marks
    /// `false` was masked out of every rule the Linux driver built, on
    /// every path, with no error and no other signal.
    features: landlock.Features,
};

/// What `spawn` hands a caller so that the caller can end a running call.
///
/// ## A reaped pid names nothing, and may soon name somebody else
///
/// `spawn` reaps the process it forked before it returns. From that moment the
/// number is free and the kernel gives it to whatever starts next, so a
/// `kill` by number after that reaches a process this session never started.
/// **Measured on 2026-08-22 on a machine that was busy building: a teardown
/// path that signalled the number unconditionally sent `SIGKILL` to a whole
/// process group that held an unrelated build.**
///
/// `fd` is what closes that. It is a `pidfd`, a descriptor that names one
/// process for as long as it is open and answers `error.Gone` once that
/// process has been reaped. **A caller signals through `fd` and never through
/// `pid`.** See `signalMiddle`.
///
/// ## Ownership
///
/// **The caller of `spawn` owns `fd` and must close it exactly once, with
/// `closeMiddle`, after the `spawn` call it came from has returned.** It is
/// deliberately not closed by `spawn` itself: the whole value of the handle is
/// that it outlives the reap and answers `error.Gone` instead of reaching a
/// stranger, which it can only do while it is open.
///
/// The two fields are written by `spawn` in a fixed order, `fd` first and then
/// `pid` with a release store, so a caller that watches `pid` for a non zero
/// value with an acquire load never reads an `fd` that is not there yet.
pub const Middle = struct {
    /// The pid of the process `spawn` forked, which is also the identifier of
    /// the process group every process of the call is in. Zero until `spawn`
    /// has forked, and zero forever if it failed before that.
    ///
    /// **This is for reporting and never for signalling.** See the type's own
    /// doc comment above.
    pid: std.posix.pid_t = 0,
    /// The handle to signal through, or -1 when there is none: the caller
    /// passed null to `spawn`, `spawn` failed before its own fork, or the
    /// platform has no such handle at all. A caller with no handle has no way
    /// to end the call early.
    fd: std.posix.fd_t = -1,
};

/// What `signalMiddle` can answer.
pub const SignalError = error{
    /// The process is already gone: it ended and was reaped, so this handle
    /// names nothing at all. **This is the answer that replaces killing a
    /// stranger**, and it is an ordinary outcome, not a fault: a caller that
    /// asks a finished call to stop has got what it asked for.
    Gone,
    /// There is no handle to signal through. See `Middle.fd`.
    NoHandle,
    /// The kernel refused the signal for a reason with no specific recovery.
    Unexpected,
};

const driver = switch (builtin.os.tag) {
    .linux => @import("linux/driver.zig"),
    .macos => @import("darwin/driver.zig"),
    else => @compileError("chock-sandbox: no driver for target os " ++ @tagName(builtin.os.tag)),
};

/// Which guarantees this build's driver actually gives. See `Guarantee`.
pub const guarantees: Guarantees = driver.guarantees;

/// Start a program in the sandbox and wait for it. See whichever driver
/// `builtin.os.tag` selects, `linux/driver.zig` or `darwin/driver.zig`, for
/// the real contract: this function only ever forwards to it and carries no
/// logic of its own. A caller that only ever reads this file's own
/// declarations, never a driver file directly, cannot tell which driver ran,
/// which is the property `chock-core` has to keep.
pub fn spawn(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    landlock_report: ?*LandlockReport,
    middle: ?*Middle,
) SpawnError!std.process.Child.Term {
    return driver.spawn(allocator, config, argv, landlock_report, middle);
}

/// Send `sig` to the process a `Middle.fd` names. See `Middle` for why a
/// caller signals through the handle and never through the number.
///
/// **Safe to call from a signal handler.** It is one syscall over a descriptor
/// the caller already holds: no allocation, no lock, and no path.
///
/// It takes the descriptor rather than the whole `Middle`, because the one
/// caller that runs in a handler, `chock_core.tools.cancelRunningTool`, holds
/// a table of plain atomics that a handler can read and cannot hold a struct.
pub fn signalMiddle(fd: std.posix.fd_t, sig: std.posix.SIG) SignalError!void {
    return driver.signalMiddle(fd, sig);
}

/// Give up a handle `spawn` opened. Does nothing when there is none, and puts
/// `fd` back to -1 so a second call cannot close a descriptor twice.
///
/// **Call this only after the `spawn` that filled the handle in has
/// returned.** See `Middle` for the ownership rule in full.
pub fn closeMiddle(middle: *Middle) void {
    driver.closeMiddle(middle);
}

/// Linux only, and only ever meaningful there: joins a fresh session
/// keyring. Exposed here so `test/sandbox/probe.zig` can call it directly,
/// outside a full `spawn`, and prove the fresh keyring really is empty; see
/// `linux/driver.zig`'s own doc comment on the function this forwards to.
/// The Darwin driver defines a stub of the same name only so the "same
/// public shape" test below stays meaningful without special casing this
/// one Linux test hook; no real caller, on either platform, has a reason to
/// call this directly.
pub const joinFreshSessionKeyring = driver.joinFreshSessionKeyring;

test "a copied config shares no memory with the original, scratch areas included" {
    // **`Config.copy` exists so a caller can outlive the arena its config was
    // built in**, which `chock_core.tasks.Table` and `chock_core.helper.Helper`
    // both do. A field the copy misses is a field the caller reads out of freed
    // memory on the first turn that ends before it does, and nothing about that
    // fault points at this function.
    //
    // The check is on the pointers and not on the values: two slices holding
    // the same bytes at the same address is exactly the fault, so equal content
    // proves nothing on its own.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const original = Config{
        .root = "/tmp/root",
        .mounts = &.{.{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } }},
        .rules = &.{.{ .path = "/work", .access = .{ .read_file = true } }},
        .scratch = &.{ .{ .target = "/run/chock/scratch" }, .{ .target = "/run/chock/tasks" } },
        .cwd = "/",
        .env = &.{"PATH=/bin"},
    };

    const copied = try original.copy(arena);

    try std.testing.expectEqual(original.scratch.len, copied.scratch.len);
    for (original.scratch, copied.scratch) |from, to| {
        try std.testing.expectEqualStrings(from.target, to.target);
        try std.testing.expect(from.target.ptr != to.target.ptr);
    }
    try std.testing.expect(original.scratch.ptr != copied.scratch.ptr);

    // The fields that were already copied before scratch areas existed, so a
    // later reader can see this test covers the whole shape and not one field.
    try std.testing.expect(original.root.ptr != copied.root.ptr);
    try std.testing.expect(original.cwd.ptr != copied.cwd.ptr);
    try std.testing.expect(original.env.ptr != copied.env.ptr);
    try std.testing.expect(original.mounts.ptr != copied.mounts.ptr);
    try std.testing.expect(original.rules.ptr != copied.rules.ptr);

    // The five numbers and the report pointer are carried across as they are,
    // on purpose: a number is not memory to duplicate, and the report points at
    // storage this function has no business copying.
    try std.testing.expectEqual(original.limits, copied.limits);
    // `net_broker` is the same case: two pointers at the caller's own storage,
    // and duplicating either one would give the copy a broker nobody answers.
    // Carried across, so a config that outlives its arena keeps its channel
    // out. **A copy with a null broker on a filtered config is refused by
    // `spawn`**, so a field this function forgot would be a plain refusal and
    // never a silent isolation: see `Config.net_broker`.
    try std.testing.expectEqual(original.net_broker, copied.net_broker);
}

test "the linux driver and the darwin driver expose the same public shape" {
    // Guarded on `builtin.os.tag`, a comptime known value, so the branch
    // this test does not take is never even imported: unconditionally
    // importing `linux/driver.zig` while compiling for Darwin is exactly
    // the mistake this whole split exists to avoid, since that file's own
    // Linux syscalls do not type check for that target. See `driver` above
    // for the same technique used for the real dispatch, not only this
    // test. This test therefore only ever runs its real check on Linux; a
    // Darwin compile of this file still proves the Darwin driver alone
    // builds, through the ordinary compile of `driver` above.
    if (builtin.os.tag != .linux) return;

    const linux_driver = @import("linux/driver.zig");
    const darwin_driver = @import("darwin/driver.zig");

    // Every name a caller can reach through this file's own driver dispatch
    // above. Add a name here whenever spawn's own dispatch starts reading a
    // new driver declaration, so a driver that falls behind fails the build
    // instead of only failing silently on the platform nobody here can run.
    const shape = .{ "spawn", "guarantees", "joinFreshSessionKeyring", "signalMiddle", "closeMiddle" };
    inline for (shape) |name| {
        if (!@hasDecl(linux_driver, name)) @compileError("linux driver is missing " ++ name);
        if (!@hasDecl(darwin_driver, name)) @compileError("darwin driver is missing " ++ name);
    }
}

test "a path a rule will name is resolved where a mount cannot be" {
    // **The fault this ends, and it was measured before it was written.** On
    // macOS `$TMPDIR` is reached below `/var`, a link to `/private/var`, and
    // Seatbelt matches the path the kernel resolved. A rule on the unresolved
    // spelling matches nothing at all, so a session whose scratchpad was named
    // that way would report every write to it as refused. `src/doctor.zig`'s
    // own probe moved off `/tmp` for the same reason on 2026-08-25.
    //
    // Mutation check: answer `path` unconditionally and the second half fails
    // wherever a mount cannot move a path.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try tmp.dir.realPath(std.testing.io, &real_buffer);
    const real = real_buffer[0..real_length];

    const through_link = try std.fmt.allocPrint(std.testing.allocator, "{s}/link", .{real});
    defer std.testing.allocator.free(through_link);
    try tmp.dir.symLink(std.testing.io, real, "link", .{ .is_directory = true });

    var answer_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const answered = resolvedPath(std.testing.io, through_link, &answer_buffer);

    if (expresses.moved_paths) {
        // The kernel resolves a bind source itself, so this costs a build that
        // moves paths nothing and changes nothing it names.
        try std.testing.expectEqualStrings(through_link, answered);
    } else {
        try std.testing.expectEqualStrings(real, answered);
    }

    // A path that is not there answers itself rather than failing: a caller
    // that could not resolve one is left with the name it had, which is what
    // the session did before this existed.
    var missing_buffer: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/no/such/directory/here",
        resolvedPath(std.testing.io, "/no/such/directory/here", &missing_buffer),
    );
}
