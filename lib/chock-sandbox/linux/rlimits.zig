//! The resource limits a sandboxed program runs under, and the reasoning for
//! each one, including the ones this project decided **not** to set.
//!
//! **The rest of the sandbox is about reach. This is about appetite.** The
//! namespaces, Landlock and seccomp between them decide what a tool call can
//! open, mount, signal and connect to. Not one of them stops a program that
//! forks until the process table is full, allocates until the machine swaps,
//! opens descriptors until the harness itself cannot open one, or writes a
//! file until the disk is full.
//!
//! ## Two mechanisms, layered, and never one instead of the other
//!
//! * **A cgroup is the right shape for memory and for process count**, and it
//!   needs a cgroup v2 tree with a delegated subtree. See `cgroup.zig`.
//! * **An rlimit needs nothing at all**: no init system, no delegation, no
//!   filesystem. It is the floor that always applies.
//!
//! So both go on. `Limits` below names one number per resource, and
//! `Sandbox.spawn` gives that number to whichever mechanisms can carry it.
//! **A machine with no cgroups still gets the floor**, and `cgroup.Support`
//! is what says out loud which half it did not get, rather than leaving a
//! person to believe in a bound that is not there.
//!
//! ## Every rlimit, and why
//!
//! **Set, with a reason:**
//!
//! * **`RLIMIT_DATA`, from `mapped_memory_bytes` and never from
//!   `memory_bytes`.** Since Linux 4.7 this bounds the program break *and*
//!   private anonymous mappings, and it does **not** count a mapped file or a
//!   shared mapping. **It bounds mapped memory, not resident memory**, which
//!   is the same defect `RLIMIT_AS` has, only narrower. See
//!   `default_mapped_memory_bytes` for the measurement that decided the
//!   default, and for why this is a separate number from the memory ceiling
//!   rather than the same one.
//! * **`RLIMIT_NOFILE`, from `open_files`.** Descriptor exhaustion is the
//!   cheapest of the three attacks to write and the least obvious in a log.
//!   **Per process**, so the real bound on a session is this times the
//!   process count, which is why the process count is bounded too.
//! * **`RLIMIT_FSIZE`, from `file_size_bytes`.** One file may not grow past
//!   this. **Read the warning under "what is not covered" below before
//!   reading this as a disk limit, because it is not one.**
//! * **`RLIMIT_CPU`, from `cpu_seconds`.** A runaway loop backstop. See "the
//!   deadline and the cpu limit are different things" below, which is the
//!   part that matters.
//! * **`RLIMIT_CORE`, always zero.** A core dump of a program that just
//!   exhausted memory is a file the size of that memory, written into
//!   whatever directory the program was in, which is the workspace. Nothing
//!   in Chock reads a core file. There is no case for keeping this on.
//! * **`RLIMIT_NPROC`, from `processes`, and only on a kernel where it means
//!   what it looks like it means.** See `nproc_per_user_namespace_since` for
//!   the measurement, which corrected what this project believed.
//!
//! **Rejected, with a reason:**
//!
//! * **`RLIMIT_AS` is not set.** It counts virtual address space, which is
//!   not memory. A garbage collected runtime, a sanitiser, and more than one
//!   ordinary allocator reserve a large region up front and touch almost none
//!   of it; every one of those is refused by an `RLIMIT_AS` that would never
//!   have been reached in resident pages. `memory.max` counts the right
//!   thing, and `RLIMIT_DATA` is the closest an rlimit gets.
//! * **`RLIMIT_STACK` is not set.** The usual 8 MiB is already a bound, a
//!   smaller one breaks ordinary compilers and recursive parsers, and a
//!   larger one is not this layer's business. Deep recursion ends in
//!   `SIGSEGV` on the guard page, which is legible on its own.
//! * **`RLIMIT_RSS` is not set.** The kernel has ignored it since Linux 2.6.
//!   Setting it would read like a memory bound and be nothing at all.
//! * **`RLIMIT_MEMLOCK`, `RLIMIT_SIGPENDING` and `RLIMIT_MSGQUEUE` are not
//!   set.** All three are already small by default, and all three have been
//!   per user namespace counters since Linux 5.14, so the fresh user
//!   namespace the sandbox enters already gives each one a fresh, bounded
//!   budget of its own.
//! * **`cpu.max` is not set** on the cgroup side either. It throttles rather
//!   than refuses, so a bounded program becomes a slow program and then dies
//!   on the wall clock deadline instead. That trades a clear failure for a
//!   confusing one, and the deadline already bounds how long a call may burn
//!   the machine.
//!
//! ## Disk, which is the row that needed a third mechanism
//!
//! Neither a cgroup nor an rlimit bounds how many bytes a program writes.
//! `RLIMIT_FSIZE` bounds **one file**, and ten thousand files of one byte each
//! still fill a filesystem. So the third mechanism is **a filesystem of the
//! sandbox's own**: an unprivileged tmpfs with a `size=` option, inside the
//! mount namespace the sandbox already takes. `scratch_bytes` below is that
//! cap, and `namespace.Scratch` holds the measurements, the mount options and
//! the reasons the other candidates were refused.
//!
//! **It does not cover the workspace, and that is a decision rather than an
//! oversight.** See `default_scratch_bytes`.
//!
//! ## What is not covered, said plainly
//!
//! * **The workspace is not capped.** It holds the agent's real work, so it
//!   stays on a real filesystem. See `default_scratch_bytes` for the whole
//!   reasoning and for what it gets instead.
//! * **Inodes, sockets, timers, and the page cache are not bounded.**
//! * **A machine with no cgroup v2 has no resident memory bound.** It has
//!   `RLIMIT_DATA`, which bounds **mapped** anonymous memory and has to sit
//!   far above the resident ceiling to let an ordinary toolchain run at all:
//!   see `default_mapped_memory_bytes`. So on such a machine a runaway
//!   allocation is stopped eventually and not promptly, and that is the
//!   honest description of it.
//! * **A machine with no cgroup v2 and a kernel older than 5.14 has no
//!   process count bound at all**, for the reason under
//!   `nproc_per_user_namespace_since`.
//!
//! ## The deadline and the cpu limit are different things
//!
//! `lib/chock-core/tools.zig` cancels a tool call that outlives
//! `default_timeout_ns`, which is **wall clock**. `RLIMIT_CPU` counts **cpu
//! time**, so a process asleep on a read is never caught by it, and a process
//! on sixteen cores burns sixteen seconds of it per second. **Neither one
//! replaces the other and a person has to be able to tell which one fired.**
//!
//! Two things make that possible:
//!
//! * `cpu_seconds` defaults well above the wall clock deadline, on purpose,
//!   so an ordinary parallel build never trips it. It is a backstop for a
//!   runaway loop in a call that has no deadline, not a second deadline.
//! * **The hard limit is set above the soft limit**, so the kernel's first
//!   answer is `SIGXCPU` and not `SIGKILL`. A tool call killed on its
//!   deadline dies from the `SIGTERM` the harness sent; one killed by
//!   `memory.max` dies from `SIGKILL`; one that burnt its cpu budget dies
//!   from `SIGXCPU`. Three different signals for three different facts. See
//!   `cpu_grace_seconds`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// The default ceiling on **resident** memory, in bytes. Carried by
/// `memory.max`, and by no rlimit at all: no rlimit bounds resident memory.
/// See `default_mapped_memory_bytes` for the one that comes closest and what
/// it really bounds.
///
/// 2 GiB is chosen to be above what a compiler needs for one translation unit
/// and below what makes an ordinary laptop swap. A project whose build really
/// needs more raises it: see `Limits`' own doc comment on where a number
/// comes from.
pub const default_memory_bytes: u64 = 2 << 30;

/// The default ceiling on **mapped** anonymous memory, in bytes, which is
/// what `RLIMIT_DATA` bounds. Far above `default_memory_bytes` on purpose,
/// and the reason is measured rather than guessed.
///
/// **Measured on 2026-08-22.** `zig build-exe` on a source file whose whole
/// content is `pub fn main() void {}`, under a series of `RLIMIT_DATA`
/// values:
///
/// * 2 GiB: `error: OutOfMemory`.
/// * 4 GiB: `error: OutOfMemory`.
/// * 8 GiB: builds.
/// * 16 GiB: builds.
///
/// The resident memory that compile really uses is a few tens of megabytes.
/// The compiler reserves a large private anonymous region up front and
/// touches almost none of it, which is exactly the behaviour that makes
/// `RLIMIT_AS` useless as a memory bound, and `RLIMIT_DATA` inherits it.
/// **This is not a theoretical objection: it broke a real test in this
/// project the first time these limits went on**, and the test was a real
/// compiler building inside the sandbox.
///
/// So the two numbers are separate. `memory_bytes` is the resident ceiling
/// and `memory.max` is what enforces it. This is a backstop against an
/// allocation loop that never stops, on a machine with no cgroups, and it has
/// to sit above what an ordinary toolchain reserves or it refuses the
/// toolchain instead.
pub const default_mapped_memory_bytes: u64 = 16 << 30;

/// The default ceiling on the number of processes and threads in one tool
/// call. Carried by `pids.max`, and by `RLIMIT_NPROC` where that means
/// something.
///
/// 256 is above `make -j` on a large machine and far below what a fork bomb
/// needs to be felt.
pub const default_processes: u64 = 256;

/// The default ceiling on open descriptors, per process.
///
/// 1024 is the historical soft default on Linux and the value nearly every
/// program is written to expect. Anything that needs more than 1024 open
/// files in one tool call is doing something a person should be asked about.
pub const default_open_files: u64 = 1024;

/// The default ceiling on the size of any one file the program writes.
///
/// 1 GiB is far above a source file, a build artefact, or a log, and far
/// below a filesystem. **This is not a disk limit.** See this file's own top
/// comment.
pub const default_file_size_bytes: u64 = 1 << 30;

/// The default cap on **one scratch area**, in bytes: the size of the tmpfs
/// `namespace.mountScratch` mounts. Carried by no rlimit and by no cgroup, for
/// the reason this file's own "disk" section gives.
///
/// ## Where 256 MiB comes from, and what it must stay below
///
/// **A tmpfs page is a memory page**, charged to the same cgroup
/// `memory_bytes` bounds, so this number and that one are one decision. See
/// `namespace.Scratch` for the measurement: a tmpfs as large as `memory.max`
/// turned a full area into an out of memory kill, which is the confusing
/// failure this project keeps paying for, while a tmpfs well under it answered
/// `ENOSPC` cleanly and the program lived to report it.
///
/// 256 MiB is an eighth of `default_memory_bytes`, so an ordinary compiler can
/// fill a scratch area completely and still have well over a gigabyte of
/// resident memory left. It is also far above what a build's temporary files
/// come to. `scratchFitsUnderMemory` is the rule, and a test in this file
/// fails if a later reader raises one of the two numbers and not the other.
///
/// ## Which writable areas get one
///
/// **An area a tmpfs can hold is one that nothing needs after the call ends.**
/// A mount lives in one call's own mount namespace and dies with it, so a
/// capped area is a **per call** area and can be nothing else. That is the
/// question to ask of each writable path, and the answers, read out of
/// `lib/chock-core/tools.zig` as it stands today, are not the ones this looked
/// like it would have:
///
/// * **The tasks output directory needs no cap at all.** It is bound **read
///   only** into the sandbox, and the harness writes it on the host. No program
///   the model runs can put a byte in it, so there is nothing to bound.
/// * **The scratchpad itself cannot take one.** It is a bind mount of a per
///   session host directory, and it is where an agent and its subagents leave
///   notes for the next call. A per call tmpfs would come up empty every call
///   and take that away. What it has instead is `scratchpad.max_bytes`, which
///   is measured **between** calls and empties the area when it is over.
///   **That cannot stop one call filling the disk**, because the next
///   measurement is the next call.
/// * **The split is built.** `lib/chock-core/scratchpad.zig` keeps the notes
///   half a bind mount and points `TMPDIR` at `scratchpad.tmp_sandbox_dir`,
///   which is a capped area of its own with no host directory behind it, and
///   `lib/chock-core/tools.zig`'s own `runCommand` names it in `Config.scratch`
///   for every `run_command` call that has a scratchpad. Temporary files are
///   what fill a disk and are exactly what nothing needs after the call.
///   `CHOCK_SCRATCHPAD` is how an agent still finds the half that survives.
/// * **A call whose limits fail `scratchFitsUnderMemory` gets no capped area**,
///   and `TMPDIR` falls back onto the scratchpad. `Limits.narrow` lets a caller
///   lower the memory ceiling and leave the cap alone, and a cap that no longer
///   fits under the ceiling turns a full area into an out of memory kill, which
///   is the confusing failure the pairing exists to prevent. See
///   `scratchpad.tempAreaFor`.
///
/// **The workspace: no, and this is the decision to read twice.** The
/// workspace holds the agent's real work, which `chock_workspace.Workspace`'s
/// own `apply` hands back at the end of a session. A tmpfs loses everything in
/// it when the machine reboots or the harness is killed, and **this project has
/// already lost a session's work once to an abnormal end**, which is why the
/// workspace an abnormal end leaves behind is now kept rather than removed. A
/// capped tmpfs workspace would undo that fix: it would trade a disk that fills
/// for work that cannot be recovered, and a filled disk is repairable while
/// lost work is not.
///
/// So the workspace stays on a real filesystem and gets a different treatment,
/// which is worth naming plainly because it is weaker:
///
/// * `RLIMIT_FSIZE` still bounds any one file in it, and still arrives as
///   `SIGXFSZ`, which names itself.
/// * **Nothing in this layer bounds the total.** A program that writes ten
///   thousand small files into its workspace can still fill the user's disk,
///   and no mechanism available to an unprivileged process refuses that write
///   without also being able to lose the work.
/// * What makes the gap smaller than it reads is that a build's temporary
///   files, which is what really fills a disk, belong in a scratch area and not
///   in the workspace. The workspace holds source, and source grows slowly.
///
/// **The treatment it gets instead is a check and not a bound, and it is
/// built.** Before each tool call that could write, `lib/chock-core/tools.zig`
/// reads the free space of the filesystem the workspace sits on, which is one
/// `statfs` and costs nothing, and refuses the call when that is under
/// `tools.default_workspace_free_floor_bytes`. It cannot stop one runaway call
/// part way through, so it is weaker than a cap, and that field's own doc
/// comment names all three ways it is weaker rather than leaving a reader to
/// find them. It is also the only shape that never loses work: it ends the
/// session with a sentence a person can act on, while every byte already
/// written is still on the disk where `Workspace.apply` can find it.
///
/// **A caller that names no workspace directory gets no floor**, which is the
/// behaviour Chock had before it existed. Only `src/run.zig` names one today.
///
/// A machine that really needs the workspace itself bounded needs privilege,
/// which is a project quota or a filesystem image, and neither is this layer's
/// to take.
pub const default_scratch_bytes: u64 = 256 << 20;

/// How many times larger the memory ceiling must be than one scratch area.
///
/// **This is the rule that stops a scratch area becoming an out of memory
/// kill.** A tmpfs page is charged to the cgroup, so an area as large as
/// `memory.max` leaves the program no memory of its own: measured on
/// 2026-08-22, an area exactly the size of `memory.max` was killed with
/// `SIGKILL` and counted an `oom_kill`, while one at three quarters of it
/// answered `ENOSPC` and the program exited normally.
///
/// Four is chosen rather than two because the measurement used a program that
/// held almost no memory of its own. A real tool call is a compiler, and a
/// compiler wants hundreds of megabytes at once, so the headroom has to be for
/// the program and not only for the arithmetic.
pub const scratch_memory_headroom: u64 = 4;

/// The default ceiling on cpu time, in seconds.
///
/// 3600 is deliberately far above `chock_core.tools.default_timeout_ns`,
/// which is 120 seconds of wall clock. The two bound different things and
/// this one must not become a second, quieter deadline: see this file's own
/// top comment. It is here so that a call with no deadline, or a program that
/// somehow survives the cancel, still ends.
pub const default_cpu_seconds: u64 = 3600;

/// How far above the soft cpu limit the hard limit sits.
///
/// **This is what makes a cpu kill legible.** With soft and hard equal the
/// kernel sends `SIGXCPU` and then `SIGKILL` one second later, and a reader
/// of the outcome sees only the `SIGKILL`, which is the same thing an out of
/// memory kill looks like. With the hard limit above the soft one, the
/// program dies from `SIGXCPU`, whose number says which limit it was.
pub const cpu_grace_seconds: u64 = 30;

/// The first kernel release where `RLIMIT_NPROC` counts per user namespace
/// rather than per user across the whole machine.
///
/// **Measured on 2026-08-22, on Linux 6.18.42, because reasoning about this
/// was giving the wrong answer.** A C program set `RLIMIT_NPROC` to 64 and
/// then forked as many children as it could:
///
/// * In the **host** user namespace, with about 3300 tasks already owned by
///   this user, **the very first fork was refused with `EAGAIN`.** That is
///   the trap: a limit set for a sandbox counts the user's own desktop, so a
///   busy machine refuses a fork the sandbox was entitled to, and a fork bomb
///   inside eats the budget the user's own shell needs.
/// * In a **fresh user namespace** with the invoking uid mapped to itself,
///   which is exactly what `namespace.enter` makes, **the same limit
///   permitted 63 children.** The counter starts at zero.
///
/// The difference is the `ucounts` rework that landed in Linux 5.14: the
/// counts behind `RLIMIT_NPROC`, `RLIMIT_MEMLOCK`, `RLIMIT_SIGPENDING` and
/// `RLIMIT_MSGQUEUE` moved to a per user namespace structure. Before it, the
/// count was one number per uid for the whole machine and the trap above was
/// real on every kernel.
///
/// So the honest answer is neither "use it" nor "it is the wrong tool":
///
/// * **`pids.max` is the right tool**, on every kernel, because it is per
///   cgroup by construction and needs no reasoning about uids at all.
/// * **`RLIMIT_NPROC` is a usable floor on 5.14 and newer**, and only there,
///   and only because the sandbox always enters a fresh user namespace before
///   this limit goes on.
/// * **On an older kernel it is not applied**, because applying it would
///   refuse the first fork of every tool call on any machine where the user
///   is already logged in.
pub const nproc_per_user_namespace_since: Release = .{ .major = 5, .minor = 14 };

/// A kernel release, for the one comparison this file makes.
pub const Release = struct {
    major: u32,
    minor: u32,

    /// True when `self` is the same as `other` or newer.
    pub fn atLeast(self: Release, other: Release) bool {
        if (self.major != other.major) return self.major > other.major;
        return self.minor >= other.minor;
    }
};

/// The numbers one sandboxed program runs under. One field per resource, not
/// one field per mechanism: a resource is bounded by a cgroup and by an
/// rlimit at once, and two fields for one resource is how two bounds quietly
/// stop agreeing.
///
/// **Null means no limit**, which is the widest a field can be. That is what
/// makes `narrow` below a minimum rather than a special case.
///
/// ## Where a number comes from
///
/// The defaults here are this library's, compiled in, and they are the
/// numbers every tool call gets today. **A number hardcoded in a source file
/// is a number somebody will hit and be unable to change**, so `Config.limits`
/// exists for a caller to name its own.
///
/// A project's own numbers belong in `chock.zon`, beside the policy table,
/// which is how this project makes anything else a project's decision. That
/// wiring is **not built**, and this comment is the honest record of why the
/// shape here is what it is:
///
/// * `chock.zon` comes out of the project directory, and a hostile project
///   writes it. So a number read from there may **lower** a limit freely and
///   may **not raise** one, which is exactly the rule
///   `lib/chock-policy/ratchet.zig` states: narrowing is free, widening needs
///   authorisation. `narrow` below is that rule written for numbers, and it
///   is the only function a reader of `chock.zon` should ever use to fold a
///   project's numbers into these.
/// * The ratchet's own machinery carries a `Decision`, which is one of five
///   named values with a total order. A byte count is not one of those, so a
///   raise cannot travel the existing `widen_action` path unchanged; it needs
///   the action to carry the number it asks for. That is a change to
///   `chock-proto` and `chock-broker`, which this milestone does not touch.
pub const Limits = struct {
    /// The **resident** memory ceiling. Carried by `memory.max`, and by
    /// nothing at all on a machine with no cgroup v2 tree: no rlimit bounds
    /// resident memory. See `mapped_memory_bytes` for the loose backstop that
    /// does apply there, and this file's own top comment for the gap said
    /// plainly.
    memory_bytes: ?u64 = default_memory_bytes,
    /// The **mapped** anonymous memory ceiling. `RLIMIT_DATA`. A different
    /// number from `memory_bytes`, and far larger, because it bounds a
    /// different thing: see `default_mapped_memory_bytes`, which holds the
    /// measurement that made these two separate fields.
    mapped_memory_bytes: ?u64 = default_mapped_memory_bytes,
    /// The process and thread ceiling. Carried by `pids.max`, and by
    /// `RLIMIT_NPROC` on a kernel where that is per user namespace.
    processes: ?u64 = default_processes,
    /// The open descriptor ceiling, per process. `RLIMIT_NOFILE`.
    open_files: ?u64 = default_open_files,
    /// The largest one file may become. `RLIMIT_FSIZE`. Not a disk limit.
    file_size_bytes: ?u64 = default_file_size_bytes,
    /// The cpu time ceiling, in seconds. `RLIMIT_CPU`. Not a deadline.
    cpu_seconds: ?u64 = default_cpu_seconds,
    /// How large one scratch area may become, in bytes. Carried by the
    /// `size=` option of the tmpfs `namespace.mountScratch` mounts, and by no
    /// rlimit and no cgroup: nothing else available to an unprivileged
    /// process bounds total bytes written. **Read
    /// `default_scratch_bytes` before raising this**, because a scratch area
    /// comes out of the same budget `memory_bytes` names.
    scratch_bytes: ?u64 = default_scratch_bytes,

    /// Every limit off. **For a test that has to prove a limit is what
    /// stopped something**, by running the same program with the limit and
    /// without it. A real caller never wants this.
    ///
    /// A null `scratch_bytes` still mounts a scratch area, with no `size=` of
    /// its own, so the unbounded half of such a test differs from the bounded
    /// half in the cap and in nothing else.
    pub const none: Limits = .{
        .memory_bytes = null,
        .mapped_memory_bytes = null,
        .processes = null,
        .open_files = null,
        .file_size_bytes = null,
        .cpu_seconds = null,
        .scratch_bytes = null,
    };

    /// The narrower of two limit sets, field by field.
    ///
    /// **This is the ratchet, written for numbers.** A caller folding a
    /// project's own numbers into the defaults can only ever end up with a
    /// smaller number, because a null is the widest value and a minimum of
    /// two numbers is never larger than either. A project that asks for more
    /// than it was given gets what it was given, and it is told so by the
    /// caller rather than quietly obeyed.
    pub fn narrow(self: Limits, other: Limits) Limits {
        return .{
            .memory_bytes = smaller(self.memory_bytes, other.memory_bytes),
            .mapped_memory_bytes = smaller(self.mapped_memory_bytes, other.mapped_memory_bytes),
            .processes = smaller(self.processes, other.processes),
            .open_files = smaller(self.open_files, other.open_files),
            .file_size_bytes = smaller(self.file_size_bytes, other.file_size_bytes),
            .cpu_seconds = smaller(self.cpu_seconds, other.cpu_seconds),
            .scratch_bytes = smaller(self.scratch_bytes, other.scratch_bytes),
        };
    }

    /// True when nothing here bounds anything, so `spawn` can skip making a
    /// cgroup it would write no limit into.
    pub fn isEmpty(self: Limits) bool {
        return self.memory_bytes == null and self.mapped_memory_bytes == null and
            self.processes == null and self.open_files == null and
            self.file_size_bytes == null and self.cpu_seconds == null and
            self.scratch_bytes == null;
    }

    /// True when one scratch area cannot push this sandbox into an out of
    /// memory kill by being filled.
    ///
    /// **A tmpfs page is charged to the cgroup `memory_bytes` bounds**, so an
    /// area that is a large part of that ceiling leaves the program no memory
    /// of its own, and a full area then arrives as a bare `SIGKILL` rather
    /// than as `ENOSPC`. That is two different faults reading the same way,
    /// which is the failure this whole layer is written to avoid. See
    /// `scratch_memory_headroom` for the measurement behind the ratio.
    ///
    /// **A null `scratch_bytes` is false when there is a memory ceiling, and
    /// the asymmetry is the point.** A null there does not mean "no area". It
    /// means an area with no `size=` of its own, which the kernel gives half
    /// the machine's memory, and that is the worst case of exactly the
    /// collision this asks about. Only a test asks for that, and only by
    /// naming `Limits.none`, where there is no memory ceiling for it to
    /// collide with.
    ///
    /// A null `memory_bytes` is true: a machine with no resident memory
    /// ceiling has nothing for a scratch area to be charged against.
    pub fn scratchFitsUnderMemory(self: Limits) bool {
        const memory = self.memory_bytes orelse return true;
        const scratch = self.scratch_bytes orelse return false;
        return scratch * scratch_memory_headroom <= memory;
    }

    /// True when a cgroup could carry something. Only two of the five have a
    /// cgroup half.
    ///
    /// **A question about these numbers, and never about who holds the
    /// cgroup.** The driver asks this only when it is about to make a cgroup
    /// of its own. A caller that supplied one wrote its own limits into it,
    /// and chock writes nothing there whatever this answers: see
    /// `../Sandbox.zig`'s own `Containment`.
    pub fn wantsCgroup(self: Limits) bool {
        return self.memory_bytes != null or self.processes != null;
    }
};

fn smaller(a: ?u64, b: ?u64) ?u64 {
    const left = a orelse return b;
    const right = b orelse return left;
    return @min(left, right);
}

/// Which call refused, and with what errno, when `apply` could not put a
/// limit on. The same shape `namespace.Diagnostic` uses, for the same reason:
/// `error.Unexpected` throws away the two facts that identify the fault, and
/// the code that fills one of these runs in a child with no allocator.
pub const Diagnostic = struct {
    limit: Which,
    errno: linux.E,

    pub const Which = enum {
        memory,
        mapped_memory,
        processes,
        open_files,
        file_size,
        cpu_time,
        core_dump,
        /// The space in one scratch area. **Not a disk**, and the wording of
        /// every sentence about it exists to keep those apart: see
        /// `Sandbox.LimitsReport.killedText`.
        scratch_space,

        /// The resource, as a phrase that reads after "the limit on ".
        pub fn text(self: Which) []const u8 {
            return switch (self) {
                .memory => "memory",
                .mapped_memory => "mapped memory",
                .processes => "the number of processes",
                .open_files => "open files",
                .file_size => "the size of one file",
                .cpu_time => "cpu time",
                .core_dump => "core dumps",
                .scratch_space => "the space in the sandbox's own scratch area",
            };
        }
    };

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("the limit on {s} could not be set: {s}", .{
            self.limit.text(),
            @tagName(self.errno),
        });
    }
};

pub const Error = error{LimitRefused};

/// Put every rlimit in `limits` on this process.
///
/// **Call this last, in the child, immediately before `execve`.** Three
/// reasons, and each one is a fault somebody would otherwise find later:
///
/// * `RLIMIT_DATA` bounds mapped anonymous memory, and this process is a
///   `fork` of the harness, so it starts out holding whatever the harness had
///   mapped. Every allocation the setup path still needs must already have
///   happened, or a limit meant for the model's program refuses the code that
///   starts it.
/// * `RLIMIT_NOFILE` must go on after Landlock, which opens one descriptor
///   per rule, and after the mount tree, which opens one per target.
/// * `RLIMIT_CPU` should start counting against the caller's program, not
///   against the sandbox coming up.
///
/// **Call it after `namespace.enter`, too.** `RLIMIT_NPROC` is what makes
/// that an ordering rule rather than a preference: see
/// `nproc_per_user_namespace_since`.
///
/// The soft and hard limits are set to the same value everywhere except cpu
/// time. **The hard limit matters:** the seccomp filter does not block
/// `prlimit64`, so a program that found only a soft limit would raise it back
/// to the hard one in one call and this whole layer would be decoration.
pub fn apply(limits: Limits, kernel: Release, diag: *?Diagnostic) Error!void {
    // A core dump is refused whatever the caller asked for. There is no
    // configuration field for this because there is no case for the other
    // answer: see this file's own top comment.
    try set(.CORE, 0, 0, .core_dump, diag);

    if (limits.mapped_memory_bytes) |bytes| try set(.DATA, bytes, bytes, .mapped_memory, diag);
    if (limits.open_files) |count| try set(.NOFILE, count, count, .open_files, diag);
    if (limits.file_size_bytes) |bytes| try set(.FSIZE, bytes, bytes, .file_size, diag);

    if (limits.cpu_seconds) |seconds| {
        // Soft below hard on purpose, so the death signal is `SIGXCPU` and
        // not `SIGKILL`. See `cpu_grace_seconds`.
        try set(.CPU, seconds, seconds + cpu_grace_seconds, .cpu_time, diag);
    }

    if (limits.processes) |count| {
        // Skipped, deliberately and silently, on a kernel where this counts
        // the user's own processes on the host. Applying it there refuses the
        // first fork of every tool call. See
        // `nproc_per_user_namespace_since`, which holds the measurement.
        if (kernel.atLeast(nproc_per_user_namespace_since)) {
            try set(.NPROC, count, count, .processes, diag);
        }
    }
}

fn set(
    resource: linux.rlimit_resource,
    soft: u64,
    hard: u64,
    which: Diagnostic.Which,
    diag: *?Diagnostic,
) Error!void {
    const value = linux.rlimit{ .cur = soft, .max = hard };
    const rc = linux.setrlimit(resource, &value);
    const set_errno = linux.errno(rc);
    if (set_errno == .SUCCESS) return;
    if (diag.* == null) diag.* = .{ .limit = which, .errno = set_errno };
    return error.LimitRefused;
}

/// This kernel's release, for the one comparison in `apply`. A release this
/// cannot parse reads as 0.0, which is older than every real kernel, so the
/// safe direction is taken: `RLIMIT_NPROC` is skipped rather than applied
/// against a number that might be counting the whole machine.
pub fn runningKernel() Release {
    var uts: linux.utsname = undefined;
    if (linux.errno(linux.uname(&uts)) != .SUCCESS) return .{ .major = 0, .minor = 0 };
    return parseRelease(std.mem.sliceTo(&uts.release, 0));
}

/// The major and minor out of a release string such as `6.18.42` or
/// `5.15.0-91-generic`.
pub fn parseRelease(release: []const u8) Release {
    var parts = std.mem.splitScalar(u8, release, '.');
    const major_text = parts.next() orelse return .{ .major = 0, .minor = 0 };
    const minor_text = parts.next() orelse return .{ .major = 0, .minor = 0 };
    const major = std.fmt.parseInt(u32, leadingDigits(major_text), 10) catch return .{ .major = 0, .minor = 0 };
    const minor = std.fmt.parseInt(u32, leadingDigits(minor_text), 10) catch return .{ .major = major, .minor = 0 };
    return .{ .major = major, .minor = minor };
}

fn leadingDigits(text: []const u8) []const u8 {
    var end: usize = 0;
    while (end < text.len and std.ascii.isDigit(text[end])) end += 1;
    return text[0..end];
}

/// The signal a program dies from when it passed a limit, or null when the
/// signal says nothing about a limit.
///
/// **This is half of what makes a limit kill legible**, and the half that
/// needs no cgroup. `cgroup.Events` is the other half, for `memory.max`,
/// which kills with a bare `SIGKILL` that reads exactly like a cancel.
pub fn limitForSignal(signal: std.posix.SIG) ?Diagnostic.Which {
    if (signal == .XCPU) return .cpu_time;
    if (signal == .XFSZ) return .file_size;
    return null;
}

test "a null limit is the widest, and narrow can only ever lower a number" {
    // The ratchet's own rule, for numbers. `chock.zon` comes out of the
    // project directory and a hostile project writes it, so folding a
    // project's numbers into these must be able to lower and must not be able
    // to raise.
    const defaults = Limits{};
    const project_asks_for_more = Limits{
        .memory_bytes = 64 << 30,
        .mapped_memory_bytes = 1 << 40,
        .processes = 100000,
        .open_files = 1 << 20,
        .file_size_bytes = 1 << 40,
        .cpu_seconds = 1 << 20,
        .scratch_bytes = 1 << 40,
    };
    const folded = defaults.narrow(project_asks_for_more);
    try std.testing.expectEqual(defaults, folded);

    const project_asks_for_less = Limits{
        .memory_bytes = 1 << 20,
        .mapped_memory_bytes = 1 << 21,
        .processes = 4,
        .open_files = 16,
        .file_size_bytes = 1024,
        .cpu_seconds = 1,
        .scratch_bytes = 4096,
    };
    try std.testing.expectEqual(project_asks_for_less, defaults.narrow(project_asks_for_less));

    // A null on either side is "no limit", which is wider than any number, so
    // the number wins. A null that behaved as zero would turn "this project
    // says nothing about descriptors" into "this project may open none".
    try std.testing.expectEqual(
        @as(?u64, 16),
        (Limits{ .open_files = null }).narrow(.{ .open_files = 16 }).open_files,
    );
    try std.testing.expectEqual(
        @as(?u64, 16),
        (Limits{ .open_files = 16 }).narrow(.{ .open_files = null }).open_files,
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        Limits.none.narrow(Limits.none).open_files,
    );

    // And the fold is a real minimum over every field at once, whichever side
    // each smaller number came from.
    const mixed = (Limits{ .memory_bytes = 100, .processes = 8 })
        .narrow(.{ .memory_bytes = 200, .processes = 4 });
    try std.testing.expectEqual(@as(?u64, 100), mixed.memory_bytes);
    try std.testing.expectEqual(@as(?u64, 4), mixed.processes);
}

test "the scratch cap cannot push the sandbox into an out of memory kill" {
    // **The two numbers are one decision.** A tmpfs page is charged to the
    // cgroup that `memory_bytes` bounds, so a scratch area near that ceiling
    // turns a full area into a bare `SIGKILL`, which reads exactly like a
    // cancel. Measured on 2026-08-22: an area the same size as `memory.max`
    // was killed and counted an `oom_kill`. One at half of it was not. See
    // `namespace.Scratch` for the whole run.
    //
    // This is the test that fails when a later reader raises one of the two
    // defaults and leaves the other alone.
    try std.testing.expect((Limits{}).scratchFitsUnderMemory());
    try std.testing.expect(default_scratch_bytes * scratch_memory_headroom <= default_memory_bytes);

    // The boundary itself, from both sides, so the rule is a real comparison
    // and not a constant that happens to be true.
    const memory: u64 = 1 << 30;
    try std.testing.expect((Limits{
        .memory_bytes = memory,
        .scratch_bytes = memory / scratch_memory_headroom,
    }).scratchFitsUnderMemory());
    try std.testing.expect(!(Limits{
        .memory_bytes = memory,
        .scratch_bytes = memory / scratch_memory_headroom + 1,
    }).scratchFitsUnderMemory());
    // The shape that was measured to be an out of memory kill: an area as
    // large as the whole memory ceiling.
    try std.testing.expect(!(Limits{
        .memory_bytes = memory,
        .scratch_bytes = memory,
    }).scratchFitsUnderMemory());

    // A null memory ceiling has nothing for an area to be charged against, so
    // there is no collision to report.
    try std.testing.expect((Limits{ .memory_bytes = null, .scratch_bytes = 1 << 40 }).scratchFitsUnderMemory());

    // **A null scratch cap under a real memory ceiling is the worst case, not
    // the absent case.** It mounts an area with no `size=`, which the kernel
    // gives half the machine's memory, so it collides harder than any number a
    // caller could write. A rule that read that null as "no area" would call
    // the one genuinely unsafe combination safe.
    try std.testing.expect(!(Limits{ .memory_bytes = 1 << 30, .scratch_bytes = null }).scratchFitsUnderMemory());

    // And `Limits.none`, which is both nulls, is the one shape that asks for
    // an uncapped area on purpose. There is no memory ceiling there either, so
    // nothing collides. Only a test ever names it.
    try std.testing.expect(Limits.none.scratchFitsUnderMemory());

    // A caller that narrows only the memory ceiling can break the rule, which
    // is why the rule is a function a caller can ask rather than a fact the
    // defaults alone carry.
    try std.testing.expect(!(Limits{}).narrow(.{ .memory_bytes = 1 << 20 }).scratchFitsUnderMemory());
}

test "a kernel release is compared by major then minor, and an unreadable one reads as old" {
    try std.testing.expectEqual(Release{ .major = 6, .minor = 18 }, parseRelease("6.18.42"));
    try std.testing.expectEqual(Release{ .major = 5, .minor = 15 }, parseRelease("5.15.0-91-generic"));
    try std.testing.expectEqual(Release{ .major = 5, .minor = 14 }, parseRelease("5.14.0"));
    try std.testing.expectEqual(Release{ .major = 6, .minor = 1 }, parseRelease("6.1.0-rc4"));

    // Anything this cannot read is 0.0, which is older than every real
    // kernel, so `apply` takes the safe branch and skips RLIMIT_NPROC rather
    // than setting a limit that might be counting the whole machine.
    try std.testing.expectEqual(Release{ .major = 0, .minor = 0 }, parseRelease(""));
    try std.testing.expectEqual(Release{ .major = 0, .minor = 0 }, parseRelease("linux"));
    try std.testing.expectEqual(Release{ .major = 0, .minor = 0 }, parseRelease("6"));

    // The boundary itself, which is the whole point of the comparison.
    try std.testing.expect((Release{ .major = 5, .minor = 14 }).atLeast(nproc_per_user_namespace_since));
    try std.testing.expect((Release{ .major = 6, .minor = 0 }).atLeast(nproc_per_user_namespace_since));
    try std.testing.expect(!(Release{ .major = 5, .minor = 13 }).atLeast(nproc_per_user_namespace_since));
    try std.testing.expect(!(Release{ .major = 4, .minor = 19 }).atLeast(nproc_per_user_namespace_since));
    try std.testing.expect(!(Release{ .major = 0, .minor = 0 }).atLeast(nproc_per_user_namespace_since));

    // The machine this is running on really can be read, whatever it is.
    // **Linux only, and the guard is not a formality.** `runningKernel` calls
    // `uname` through `std.os.linux`, which is a raw syscall number that
    // means something else entirely on Darwin: measured on 2026-08-22, this
    // line ended the whole Darwin test binary with `SIGABRT`. This file is
    // compiled for Darwin because `Sandbox.zig` names its types, the same way
    // it names `landlock.AccessFs`; nothing in it ever runs there.
    if (builtin.os.tag != .linux) return;
    try std.testing.expect(runningKernel().major > 0);
}

test "a diagnostic names the resource and the errno, and every resource reads differently" {
    var buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "the limit on memory could not be set: PERM",
        try std.fmt.bufPrint(&buffer, "{f}", .{Diagnostic{ .limit = .memory, .errno = .PERM }}),
    );

    const all = std.enums.values(Diagnostic.Which);
    for (all, 0..) |which, i| {
        try std.testing.expect(which.text().len > 0);
        for (all[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, which.text(), other.text()));
        }
    }
}

test "the two limits that kill say which one they were, through the signal number" {
    // The whole reason the cpu hard limit sits above the soft one. A
    // sandboxed program can die from SIGTERM (the harness cancelled it),
    // SIGKILL (out of memory, or something else killed it outright), SIGXCPU
    // (it burnt its cpu budget) or SIGXFSZ (it wrote past the file size
    // limit), and a person reading the outcome has to be able to tell them
    // apart.
    try std.testing.expectEqual(
        @as(?Diagnostic.Which, .cpu_time),
        limitForSignal(std.posix.SIG.XCPU),
    );
    try std.testing.expectEqual(
        @as(?Diagnostic.Which, .file_size),
        limitForSignal(std.posix.SIG.XFSZ),
    );

    // A cancel and an out of memory kill are not limits this half can name.
    // SIGKILL in particular is the one `cgroup.Events` exists to explain.
    try std.testing.expectEqual(
        @as(?Diagnostic.Which, null),
        limitForSignal(std.posix.SIG.TERM),
    );
    try std.testing.expectEqual(
        @as(?Diagnostic.Which, null),
        limitForSignal(std.posix.SIG.KILL),
    );
    try std.testing.expectEqual(
        @as(?Diagnostic.Which, null),
        limitForSignal(std.posix.SIG.SEGV),
    );
}

test "apply really sets the limits, in a forked child that cannot take this process with it" {
    // Linux only. `setrlimit` here is a raw Linux syscall number, and this
    // file is compiled for Darwin only because `Sandbox.zig` names its types.
    // See the guard in the release test above, which this project measured
    // the hard way.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // A forked child, for the reason every other test in this library that
    // calls a setup step directly uses one: these limits are irreversible in
    // the process that takes them, and a test runner that gave itself
    // RLIMIT_NOFILE of 16 could not report its own results.
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        var diag: ?Diagnostic = null;
        // No RLIMIT_NPROC and no RLIMIT_DATA here: this child is a fork of a
        // test runner whose address space is already mapped, and it has to
        // survive long enough to report. The three below have no such
        // hazard, and the escape tests exercise the full set through a real
        // `spawn`.
        apply(.{
            .memory_bytes = null,
            .mapped_memory_bytes = null,
            .processes = null,
            .open_files = 42,
            .file_size_bytes = 4096,
            .cpu_seconds = 1234,
        }, runningKernel(), &diag) catch std.process.exit(2);

        var read_back: linux.rlimit = undefined;
        var ok = true;

        _ = linux.getrlimit(.NOFILE, &read_back);
        ok = ok and read_back.cur == 42 and read_back.max == 42;

        _ = linux.getrlimit(.FSIZE, &read_back);
        ok = ok and read_back.cur == 4096 and read_back.max == 4096;

        // Soft below hard, which is what makes a cpu kill arrive as SIGXCPU.
        _ = linux.getrlimit(.CPU, &read_back);
        ok = ok and read_back.cur == 1234 and read_back.max == 1234 + cpu_grace_seconds;

        // And the core dump, which is off whatever the caller asked for.
        _ = linux.getrlimit(.CORE, &read_back);
        ok = ok and read_back.cur == 0 and read_back.max == 0;

        // The hard limit really is a hard limit: raising the soft one back
        // must be refused, or a sandboxed program lifts every limit here in
        // one call and this layer is decoration.
        const raise = linux.rlimit{ .cur = 4096, .max = 4096 };
        const refused = linux.errno(linux.setrlimit(.NOFILE, &raise)) == .PERM;
        ok = ok and refused;

        std.process.exit(if (ok) 0 else 1);
    }

    var status: u32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}
