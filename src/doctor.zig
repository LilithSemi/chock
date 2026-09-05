//! `chock doctor`: ask, **before** a session starts, whether this machine can
//! contain one.
//!
//! The header of a running session already names the sandbox layers. That is
//! too late for a person deciding whether to trust the box at all, and it says
//! nothing on a machine where a session cannot start. This command answers the
//! same question with no session, no workspace, and no provider call.
//!
//! ## The state that had no producer until now
//!
//! `src/ui.zig`'s own `Layer.State.unavailable` means "the machine could give
//! this layer and this process was not permitted". Nothing in a session
//! produces it, because the Linux driver refuses to spawn rather than degrade,
//! so a running session never has an available but unapplied layer. **Before a
//! session, that answer is the useful one**, and this command is its home.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_broker = @import("chock-broker");
const chock_container = @import("chock-container");
const chock_core = @import("chock-core");
const chock_io = @import("chock-io");
const chock_nix = @import("chock-nix");
const chock_pcsc = @import("chock-pcsc");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const sandbox = @import("chock-sandbox");

const session_paths = @import("session.zig");
/// **One list of host system directories, read by both.** A report that
/// counted a different set from the one a session binds would be a second
/// answer to keep true. See `run.host_toolchain_candidates`.
const run = @import("run.zig");
const Exit = @import("main.zig").Exit;
/// What `chock --version` prints, printed here too. **Read from `src/main.zig`
/// and never spelled again**: a second copy of the line is a second thing to
/// keep true, and the number itself comes from `build.zig.zon` alone.
const version_line = @import("main.zig").version_line;
const tty = @import("tty.zig");
const ui = @import("ui.zig");

const linux = std.os.linux;

const usage_text =
    \\Usage: chock doctor [options]
    \\
    \\Says whether a session can start on this machine, one layer at a time,
    \\and what to do about a row that is not on.
    \\
    \\Exits 0 when a first run can work here, and 2 when it cannot. A machine
    \\that works with a layer missing still exits 0 and says which layer, so a
    \\script gets one answer and a person gets the whole report.
    \\
    \\A row that is on is a glyph, a name and OK. A row that is not on also says
    \\what is lost and what to do about it. With --verbose every row that is on
    \\says what it gives as well, and the report says what redaction is not.
    \\
    \\Options:
    \\  --project <dir>   The project. Defaults to the current directory.
    \\
++ tty.options_text;

const Options = struct {
    project: ?[]const u8 = null,
};

/// What one probe found.
///
/// **Three answers and no fourth.** A row can never be built from something
/// nobody measured, which is the fault this whole command exists to avoid: a
/// column of `unsupported` that was guessed from the platform reads like a
/// report and says nothing.
pub const Probe = union(enum) {
    /// The layer went on when this command asked for it.
    ok,
    /// This machine does not have the layer at all, so there is nothing to
    /// configure. The text says how that was learned.
    absent: []const u8,
    /// The machine has the layer and this process was not permitted to use
    /// it. The text says what refused.
    refused: []const u8,

    /// The same four state record `src/ui.zig` uses for the session header.
    /// `off` is never produced here: nothing in a report gives a layer up.
    pub fn state(self: Probe) ui.Layer.State {
        return switch (self) {
            .ok => .on,
            .absent => .unsupported,
            .refused => .unavailable,
        };
    }

    /// Why, in a person's words. Empty for a layer that is on.
    pub fn why(self: Probe) []const u8 {
        return switch (self) {
            .ok => "",
            .absent, .refused => |text| text,
        };
    }
};

/// What `chock_sandbox`'s cgroup layer answered. Named through the field it
/// fills in on a real `spawn`, so this file states no second copy of the type.
pub const CgroupSupport = @FieldType(sandbox.Sandbox.LimitsReport, "cgroup");

/// Which machine the cgroup answer is about. See `cgroup.Vantage`: the path
/// that answer is derived from is relative to a cgroup namespace, so a process
/// inside one can be refused by a machine that delegates.
pub const CgroupVantage = sandbox.cgroup.Vantage;

/// What this project's Nix dev shell did.
pub const DevShellState = union(enum) {
    /// The project states no `flake.nix`. Tool calls then use whatever the
    /// `toolchain` row says, which is the answer for a project that states
    /// nothing.
    no_flake,
    /// The dev shell was read. True when this command evaluated it, false
    /// when it read the cache a session would read.
    read: bool,
    /// `nix` could not read it. A session still runs: a broken `flake.nix` is
    /// often the very thing somebody starts a session to fix.
    failed: []const u8,
    /// There is a `flake.nix` and no `nix` to read it with.
    no_nix,
};

/// What a container runtime on this machine answered.
///
/// **This row adds nothing to the guarantee columns and must never appear to.**
/// `Measured.driver` stays `sandbox.Sandbox.guarantees` whatever this says: a
/// tool call gets the same boundary whether its files came from a Nix closure,
/// from a rootless Podman or from a root Docker daemon. What this says is a
/// different fact on a different axis, which is who put the files on the disk.
/// See `chock_container.Runtime.Trust`.
pub const ContainerState = union(enum) {
    /// No runtime is on this machine's `PATH`. **Not a gap**: only a project
    /// that names an image needs one.
    not_installed,
    /// A runtime is installed and did not answer. The sentence is the
    /// runtime's own, through `chock_container.Runtime`.
    unreachable_runtime: []const u8,
    ready: Ready,

    pub const Ready = struct {
        kind: chock_container.Runtime.Kind,
        /// The absolute path of the program, from `Runtime.detect`.
        ///
        /// **Absolute, and this is not decoration.** `chock_container.proc.run`
        /// asserts that `argv[0]` is absolute, so a row that kept only the
        /// kind and rebuilt a bare program name aborted the whole command in a
        /// debug build. Measured on 2026-08-25 with a real podman.
        program: []const u8,
        /// What privilege the program that unpacks an image holds.
        /// **`Trust.isPrivileged` reads as a warning and never as a failed
        /// layer.** A root daemon is a weaker trust position, not a broken
        /// sandbox.
        trust: chock_container.Runtime.Trust,
    };
};

/// Where the files a tool call would run come from, if a session started now.
///
/// **This is the row that stops `chock doctor` saying a session can start on a
/// machine where no tool call can work.** Measured on 2026-08-25 on a bare
/// Debian with no Nix: every row of the report passed, the session started,
/// the model answered, and the first tool call died in the mount tree. Seven of
/// the seventeen rows blocked a first run and the dev shell row was not one of
/// them, because a dev shell really is optional. What is not optional is that
/// something has to be mounted.
pub const ToolchainState = union(enum) {
    /// The project's own Nix dev shell answered. The narrowest of the three.
    dev_shell,
    /// The project names this image and it is on this machine.
    image: []const u8,
    /// The project names this image and a session could not read it. The text
    /// says why and what to run. **This blocks.**
    image_unusable: []const u8,
    /// The project states neither, so a session mounts this many of the host's
    /// own system directories. See `src/run.zig`'s own `Toolchain`.
    host: usize,
    /// Not one of the host's system directories is there either. **This
    /// blocks**: a session would start and every tool call in it would fail.
    none,
};

/// One audit sink this installation's org policy bundle requires, and whether
/// this machine can reach it. See `reachSink`.
pub const SinkProbe = struct {
    /// Which transport, as the bundle named it.
    kind: chock_policy.org.RequiredSink.Kind,
    /// What the bundle named: the directory for a drop, the socket for
    /// syslog. **Never the probe file opened inside a directory**, because the
    /// path a person has to act on is the one their organisation wrote.
    path: []const u8,
    reached: Probe,
};

/// Whether this machine has a credential for the provider a session would
/// use.
pub const CredentialState = union(enum) {
    /// One was found. The text names which of the three sources answered.
    found: []const u8,
    /// The provider asks for none, which is what a local endpoint is. See
    /// `chock_auth.lookup.Source.none`.
    not_needed,
    /// The provider needs one and none was found, so no session against it
    /// can work. The text names the instance, never any part of a value.
    /// See `chock_auth.lookup.credentialIsMissing`.
    missing: []const u8,
    /// There is no configuration, or it names no provider or no model. A
    /// session cannot start.
    unconfigured: []const u8,
    /// The configuration is there and the credential could not be read.
    unreadable: []const u8,
};

/// Which set of layers this build's driver applies, and so which rows the
/// report has.
///
/// **Read from the driver's own guarantees and never from `builtin.os.tag`.**
/// Two platforms with two mechanisms answer the same questions in two
/// vocabularies, and a column of Linux rows on a Mac would name six things that
/// machine has never heard of.
pub const LayerFamily = enum {
    /// No layer at all. `Sandbox.spawn` refuses before it forks, and the report
    /// is one sentence: see `refuses_outright`.
    none,
    /// Namespaces, Landlock, seccomp, a cgroup and a capped tmpfs. The Linux
    /// driver.
    namespaces,
    /// Seatbelt and Darwin's own resource limits. The Darwin driver.
    seatbelt,

    /// The family a driver with these guarantees belongs to.
    ///
    /// **`workspace_mounted` is what tells the two families apart**, and it is
    /// the honest question: a driver that can put the workspace at the
    /// project's own path has a mount namespace, and every other Linux layer
    /// stands beside that one. A driver that gives layers without it is the
    /// Darwin driver, where the workspace stays where it is: see
    /// `lib/chock-workspace/layout.zig`.
    pub fn forDriver(given: sandbox.Sandbox.Guarantees) LayerFamily {
        if (given.count() == 0) return .none;
        return if (given.contains(.workspace_mounted)) .namespaces else .seatbelt;
    }
};

pub const Measured = struct {
    /// What this build's sandbox driver says it gives. **Read from the driver
    /// and never from `builtin.os.tag`.** An empty set is what makes
    /// `Sandbox.spawn` refuse before it does anything.
    driver: sandbox.Sandbox.Guarantees = sandbox.Sandbox.guarantees,
    /// Which rows this report has. Follows `driver` for a real run, and a test
    /// sets both together to state a machine this one is not.
    family: LayerFamily = LayerFamily.forDriver(sandbox.Sandbox.guarantees),

    /// Whether a Seatbelt profile really confined a child of this process.
    /// **Darwin only**, and measured by spawning a real sandbox that tries to
    /// read a path outside itself: see `measureSeatbelt`.
    seatbelt: Probe = .{ .absent = layer_not_measured },
    /// Whether the three resource limits Darwin honours went on. **Darwin
    /// only.** The other four have no Darwin mechanism at all and are stated,
    /// not measured: see `lib/chock-sandbox/darwin/limits.zig`.
    rlimits: Probe = .{ .absent = layer_not_measured },
    /// Why a whole tool call is still refused on this build, or null when one
    /// runs. **Darwin only**, and the one row that decides the exit code
    /// there: see `toolCallRow`.
    tool_call_refused: ?[]const u8 = null,

    user_namespace: Probe = .{ .absent = driver_gives_nothing },
    mount_namespace: Probe = .{ .absent = driver_gives_nothing },
    pid_namespace: Probe = .{ .absent = driver_gives_nothing },
    ipc_namespace: Probe = .{ .absent = driver_gives_nothing },
    network_namespace: Probe = .{ .absent = driver_gives_nothing },
    landlock: Probe = .{ .absent = driver_gives_nothing },
    /// The Landlock ABI version the kernel answered, or null when it has
    /// none. Shown beside the row, because a kernel with Landlock and an old
    /// ABI silently gives a smaller ruleset than the design asks for.
    landlock_abi: ?i32 = null,
    seccomp: Probe = .{ .absent = driver_gives_nothing },
    /// Whether a page could be writable and executable at the same time in a
    /// session of this project. **Read from the project's own policy and not
    /// from the machine**: every machine can hold this rule, and the only
    /// question is whether the project asked to give it up. See
    /// `chock_policy.hardening`, and `measureHardening` below.
    write_execute: chock_policy.hardening.WriteExecute = .strict,
    /// What `cgroup.Cgroup.create` answered, or null when no driver asked.
    cgroup: ?CgroupSupport = null,
    /// Which machine that answer is about, or null when no driver asked.
    cgroup_vantage: ?CgroupVantage = null,
    overlayfs: Probe = .{ .absent = driver_gives_nothing },
    pidfd: Probe = .{ .absent = driver_gives_nothing },
    tmpfs: Probe = .{ .absent = driver_gives_nothing },

    /// Where `git` is, or null when it is not on this machine's PATH.
    ///
    /// **A session needs it, and the report had no row for it.** Measured on
    /// 2026-08-25: with no git, `chock run` answers "the workspace for /proj
    /// could not be built: NotFound" and never says the word git.
    git_program: ?[]const u8 = null,
    /// Where `nix` is, or null when it is not on this machine's PATH.
    nix_program: ?[]const u8 = null,
    dev_shell: DevShellState = .no_flake,
    /// What a container runtime on this machine answered. See
    /// `ContainerState`.
    container: ContainerState = .not_installed,
    /// Where the files a tool call would run come from. See `ToolchainState`.
    ///
    /// **The default is the answer a report that measured nothing must give**:
    /// no dev shell, no image, and no host directory found, which blocks. A
    /// test that states a healthy machine states this too.
    toolchain: ToolchainState = .none,
    credential: CredentialState = .{ .unconfigured = "the configuration was not read" },
    /// Whether the toolchain cache directory could be made.
    cache: Probe = .{ .refused = "the toolchain cache was not read" },
    /// Free bytes on the filesystem the workspace lives on, or null when that
    /// could not be read. **Null is never a zero**: an unreadable filesystem
    /// is not a full one, the same rule `chock_io.Io.freeBytes` keeps.
    free_bytes: ?u64 = null,

    /// Whether this machine can reach a PC/SC daemon, and how many readers it
    /// said are attached.
    ///
    /// **Reached for, and never worked out from the platform.** The probe is
    /// `chock_pcsc.Driver`, the transport a card seal is signed over, so this
    /// command states no second connect and no second handshake.
    ///
    /// **This row says what a card seal would find, and never that one was
    /// made.** `chock sessions seal` reaches the same transport on every run
    /// and reports which key really signed: see `sessions.sealMain` and
    /// `chock_pcsc.attempt`. A daemon that names a reader here does not mean
    /// that card holds a key. See `measureCardSeal`.
    card_seal: Probe = .{ .absent = "the PC/SC transport was not read" },
    /// How many readers the daemon named, or null when it was never asked.
    /// **Null is never a zero**: a daemon that refused this client said nothing
    /// about what is plugged into the machine.
    card_readers: ?usize = null,

    /// Every sink this installation's org policy bundle requires, one entry
    /// each, in the order the bundle names them.
    ///
    /// **Empty is the ordinary answer**, and it is the answer for an
    /// installation nobody gave a bundle, for a bundle that requires no sink,
    /// and for a build that measured nothing. So a machine with no bundle
    /// gains no row and reads exactly as it did before export was a control.
    required_sinks: []const SinkProbe = &.{},
};

/// The reason every layer carries on a build whose driver gives no layer at
/// all. **One sentence about the driver, not six sentences about a kernel
/// nobody asked.**
pub const driver_gives_nothing =
    "this build's sandbox driver applies no layer, so it refuses to run a tool call at all";

/// The reason a layer of a family this build is not in carries. **Never
/// printed on a real run**: a row is only built for the family the driver is
/// in, and every layer of that family is measured before `rowsFor` is called.
pub const layer_not_measured = "this build's sandbox driver was never asked about it";

/// One line of the report.
pub const Row = struct {
    /// What the row is called. Short, because it is a column.
    name: []const u8,
    state: ui.Layer.State,
    /// What this machine answered, in a person's words. **Never empty for a
    /// row that is not on**: a fault a report states without a reason is a
    /// report a person has to already understand.
    ///
    /// **Empty is allowed for a row that is on**, and it is the ordinary case.
    /// A layer that works has nothing to report but the word `OK`. A row that
    /// measured a value keeps it here, because a number is an answer and not a
    /// lesson: the Landlock ABI, the path of `nix`, the free space.
    means: []const u8,
    /// What this row gives when it is on, for a reader who has not met it
    /// before. **Printed only when the row is on and only with `--verbose`.**
    ///
    /// This is a teaching and not an answer. It is the same sentence on every
    /// machine and on every run, so a person who has read it once gets nothing
    /// from the second time. A row that is not on says what is lost in `means`
    /// and what to do in `fix`, and both of those are printed always.
    why: []const u8 = "",
    /// What to do about it. Empty when the row is on, and empty when nothing
    /// can be done, which is itself said in `means`.
    fix: []const u8 = "",
    /// True when a first run fails **because of this row, as measured**.
    /// The exit code is built from this and from nothing else: see
    /// `verdictFor`.
    ///
    /// **A property of the measurement and not only of the row's name.** Two
    /// rows can carry the same name, the same state and different answers
    /// here: free space that could not be read refuses no tool call, and free
    /// space that was read and is under the floor refuses every writing one.
    blocks: bool = false,
};

/// The heading each half of the report carries.
pub const layers_heading = "Sandbox layers";
pub const first_run_heading = "Before a first run";

/// The one sentence a build whose driver gives no layer answers with.
///
/// **A different fact deserves a different sentence.** A column of
/// `unsupported` rows reads as a machine that is nearly ready and needs a
/// setting changed. This is a build that refuses outright, and no row of a
/// table says that. Linux and macOS each have a driver and each get rows: see
/// `LayerFamily`.
pub const refuses_outright =
    "chock doctor: no session can start with this build. Its sandbox driver applies no layer, " ++
    "and Sandbox.spawn refuses before it forks rather than run a tool call unprotected. " ++
    "This is a build for a target Chock has no sandbox driver for. There is nothing to " ++
    "configure and no layer below to turn on.";

/// What the whole report says, in one word.
pub const Verdict = enum {
    /// Every row is on.
    ready,
    /// A row is not on and no row that is not on stops a first run.
    degraded,
    /// A first run fails on this machine.
    blocked,
};

/// The verdict `rows` carry.
///
/// **`blocked` is decided by `Row.blocks` alone.** A machine with no cgroup
/// delegation is degraded and works; a machine with no Landlock is blocked,
/// because `Sandbox.spawn` refuses without it. Grading those the same way
/// would make this command useless as a gate, which is the whole reason a
/// script would run it.
pub fn verdictFor(rows: []const Row) Verdict {
    var verdict: Verdict = .ready;
    for (rows) |row| {
        if (row.state == .on) continue;
        if (row.blocks) return .blocked;
        verdict = .degraded;
    }
    return verdict;
}

/// The exit code for a verdict.
///
/// **Zero means a first run can work here, and nothing else.** `faulted` is
/// the refusal, and it is deliberately not `usage`: that code already means
/// the command line was wrong, and a script that read the two the same way
/// would answer a broken machine by printing its own help.
pub fn exitFor(verdict: Verdict) Exit {
    return switch (verdict) {
        // A degraded machine runs. Saying so is the report's job, not the
        // exit code's.
        .ready, .degraded => .finished,
        .blocked => .faulted,
    };
}

/// The word beside the glyph.
///
/// **The word follows `Row.blocks` and never the state alone.** A row carries
/// two facts: whether this machine has the layer, and whether a first run
/// stops here. The column is what a person scans, so it answers the second,
/// and `BLOCKED` stands beside exactly the rows the footer counts. Measured on
/// a Mac on 2026-08-25: two rows said `BLOCKED` and the footer said one row
/// stops a first run, because the word came from the state. **A report that
/// disagrees with itself teaches a reader to trust neither half**, and a
/// `BLOCKED` on a machine that runs is the same fault as an `OK` on a machine
/// that does not, pointing the other way.
///
/// **Not `ui.Layer.State.word`, and that is on purpose.** The session header
/// leaves a layer that is on with no word at all, because a row of layers
/// reads as healthy when nothing is said. A report is a table, and a blank
/// cell in a table reads as a measurement nobody took.
pub fn wordFor(row: Row) []const u8 {
    if (row.state == .on) return "OK";
    if (row.blocks) return "BLOCKED";
    return switch (row.state) {
        // A row that is on and blocks is not a state this file builds: a first
        // run cannot fail on a layer that went on.
        .on => unreachable,
        // The header's own two words for a machine and never for a verdict.
        // `OFF` is a layer that was given up and `NONE` is a machine with
        // nothing to configure, and neither was ever read as a refusal.
        .off, .unsupported => row.state.word(),
        // The state whose header word is `BLOCKED`. Here the machine has the
        // layer, this process may not use it, and the session still starts. So
        // the word says what the run loses, which is what the footer says too.
        .unavailable => "DEGRADED",
    };
}

/// Every row, in the order a person reads them. Caller owns the slice, which
/// for a real caller is an arena.
///
/// **Nothing here reaches the kernel.** Every fact is already in `m`, which is
/// what lets a test state a machine that this one is not.
pub fn rowsFor(arena: std.mem.Allocator, m: Measured) std.mem.Allocator.Error![]const Row {
    var rows: std.ArrayList(Row) = .empty;

    // A driver that applies no layer gets no layer rows. See
    // `refuses_outright` for the sentence it gets instead. A driver that
    // applies Seatbelt gets Darwin's own rows and none of the eleven below,
    // because that machine has none of the eleven mechanisms.
    if (m.family == .seatbelt) try appendSeatbeltRows(arena, m, &rows);
    if (m.family == .namespaces) {
        try rows.append(arena, .{
            .name = "user namespace",
            .state = m.user_namespace.state(),
            .means = if (m.user_namespace == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "a tool call would keep your own user id: {s}", .{
                    m.user_namespace.why(),
                }),
            .why = "this process can make one, so a tool call runs as a user id of its own",
            .fix = if (m.user_namespace == .ok) "" else
            // The one setting an administrator really can change, named
            // exactly, because "check your kernel" costs a person an hour.
            "Every other layer is built on this one. Set kernel.unprivileged_userns_clone to 1, " ++
                "or remove the container or policy that turns it off.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "mount namespace",
            .state = m.mount_namespace.state(),
            .means = if (m.mount_namespace == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "the workspace cannot be mounted: {s}", .{
                    m.mount_namespace.why(),
                }),
            .why = "the workspace can appear at the project's own path and nothing else can",
            .fix = if (m.mount_namespace == .ok) "" else "This is the layer Sandbox.spawn is named after. Without it there is no sandbox.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "pid namespace",
            .state = m.pid_namespace.state(),
            .means = if (m.pid_namespace == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "a tool call could signal any process you own: {s}", .{
                    m.pid_namespace.why(),
                }),
            .why = "a tool call sees its own processes and can signal no other",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "ipc namespace",
            .state = m.ipc_namespace.state(),
            .means = if (m.ipc_namespace == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "shared memory would cross the boundary: {s}", .{
                    m.ipc_namespace.why(),
                }),
            .why = "shared memory and message queues do not cross the boundary",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "net namespace",
            .state = m.network_namespace.state(),
            .means = if (m.network_namespace == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "a tool call would reach the network freely: {s}", .{
                    m.network_namespace.why(),
                }),
            .why = "a tool call reaches no host unless a policy brokers the connection",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "landlock",
            .state = m.landlock.state(),
            // **The ABI number stays on the row that is on.** It is a
            // measurement and it differs between machines: an old kernel gives
            // a smaller ruleset than the design asks for, and only the number
            // says so.
            .means = if (m.landlock == .ok)
                (if (m.landlock_abi) |abi| try std.fmt.allocPrint(arena, "ABI {d}", .{abi}) else "")
            else
                try std.fmt.allocPrint(arena, "no path restriction at all: {s}", .{
                    m.landlock.why(),
                }),
            .why = "the paths a tool call may open are named by the kernel itself",
            .fix = if (m.landlock == .ok) "" else "Landlock needs kernel 5.13 or later and lsm=landlock on the kernel command line. " ++
                "Sandbox.spawn refuses without it rather than run with one layer missing.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "seccomp",
            .state = m.seccomp.state(),
            .means = if (m.seccomp == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "no system call filter: {s}", .{m.seccomp.why()}),
            .why = "the system calls a tool call may make are filtered",
            .fix = if (m.seccomp == .ok) "" else "The filter needs CONFIG_SECCOMP_FILTER and no_new_privs. Sandbox.spawn refuses without it.",
            .blocks = true,
        });

        // **A row of its own, because a session that gave this up must not read
        // the same as one that kept it.** It sits under `seccomp` because it is
        // one rule of that filter, and it is the only sandbox row here that is a
        // question about the project rather than about the machine: see
        // `measureHardening`.
        //
        // `off` and never `unsupported` or `unavailable`. Those two say the
        // machine cannot give the layer, or would not let this process have it,
        // and neither is true. This session can have it and the project asked
        // for it to be given up, which is exactly what `ui.Layer.State.off`
        // means.
        //
        // **It does not block a first run.** W^X is documented hardening and it
        // is not a boundary: `test/redteam/scope.zig` retires it by name, and
        // `lib/chock-sandbox/linux/seccomp.zig` gives three measured ways past
        // it. A project that asked for this gets a session, and gets told.
        try rows.append(arena, .{
            .name = "write^execute",
            .state = switch (m.write_execute) {
                .strict => .on,
                .relaxed => .off,
            },
            .means = switch (m.write_execute) {
                .strict => "",
                .relaxed => try std.fmt.allocPrint(
                    arena,
                    "this project's policy answers allow for {s}, so a page can be writable and " ++
                        "executable at the same time",
                    .{chock_policy.hardening.jit_action},
                ),
            },
            .why = "a page cannot be writable and executable at the same time, which raises the cost of running injected code",
            .fix = switch (m.write_execute) {
                .strict => "",
                .relaxed => "A run time with a just in time compiler needs this. Every other layer is " ++
                    "unchanged, and an organisation can refuse it with one rule in its policy bundle.",
            },
            .blocks = false,
        });

        try rows.append(arena, .{
            .name = "pidfd",
            .state = m.pidfd.state(),
            .means = if (m.pidfd == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "a call could not be cancelled safely: {s}", .{
                    m.pidfd.why(),
                }),
            .why = "a cancelled tool call is signalled by handle, so a late cancel reaches nothing rather than a stranger",
            .fix = if (m.pidfd == .ok) "" else "pidfd_open needs kernel 5.3 or later. Any kernel with Landlock already has it, " ++
                "so a machine that fails only here is unusual and worth reporting.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "disk cap tmpfs",
            .state = m.tmpfs.state(),
            .means = if (m.tmpfs == .ok)
                ""
            else
                try std.fmt.allocPrint(arena, "no capped writable area: {s}", .{m.tmpfs.why()}),
            .why = "the sandbox's own writable areas are held in memory with a hard cap on each",
            .fix = if (m.tmpfs == .ok) "" else "A tmpfs is the only capacity limit an unprivileged process can put on a filesystem, " ++
                "and Sandbox.spawn refuses rather than give an uncapped directory instead.",
            .blocks = true,
        });

        try rows.append(arena, .{
            .name = "overlayfs",
            .state = m.overlayfs.state(),
            .means = if (m.overlayfs == .ok)
                ""
            else
                try std.fmt.allocPrint(
                    arena,
                    "a project with no git of its own has no workspace: {s}",
                    .{m.overlayfs.why()},
                ),
            .why = "a project with no git of its own still gets a workspace",
            .fix = if (m.overlayfs == .ok) "" else "A git project is unaffected: it gets a worktree. Rootless overlayfs needs kernel 5.11 or later.",
            // Deliberately not blocking. Only a project with no git of its
            // own needs an overlay, and this command does not run `git` to
            // find out, so it says which projects are affected instead of
            // refusing for every project.
            .blocks = false,
        });

        try rows.append(arena, try cgroupRow(arena, m.cgroup, m.cgroup_vantage));
    }

    try rows.append(arena, gitRow(m));
    try rows.append(arena, nixRow(m));
    try rows.append(arena, try devShellRow(arena, m.dev_shell));
    if (try containerRow(arena, m.container, m.toolchain)) |row| try rows.append(arena, row);
    try rows.append(arena, try toolchainRow(arena, m.toolchain));
    try rows.append(arena, try credentialRow(arena, m.credential));
    try rows.append(arena, try cacheRow(arena, m.cache));
    try rows.append(arena, try freeSpaceRow(arena, m.free_bytes));
    try rows.append(arena, try cardSealRow(arena, m.card_seal, m.card_readers));
    // One row each, and none at all for an installation with no bundle. See
    // `Measured.required_sinks`.
    for (m.required_sinks) |one| try rows.append(arena, try requiredSinkRow(arena, one));

    return rows.toOwnedSlice(arena);
}

/// The name of the row that says whether a whole tool call can run on a
/// Seatbelt build. Named once, because a test reads it and `rowsFor` writes it.
pub const tool_call_name = "tool call";

/// Every row a Seatbelt build has, in the order a person reads them.
///
/// **Two halves, and the second one is the point.** The first four rows are
/// layers this driver really applies, each one measured or proved by a test
/// that tried to break it on a real Mac. The rest are the layers Linux has and
/// macOS has not, one row each, every one `NONE` rather than `BLOCKED`: there
/// is no setting to change and no version of macOS that closes any of them. A
/// person reading this column should be able to see, without reading any other
/// file, exactly what a session on this machine is and is not bounded by.
fn appendSeatbeltRows(
    arena: std.mem.Allocator,
    m: Measured,
    rows: *std.ArrayList(Row),
) std.mem.Allocator.Error!void {
    try rows.append(arena, .{
        .name = "seatbelt",
        .state = m.seatbelt.state(),
        .means = if (m.seatbelt == .ok)
            ""
        else
            try std.fmt.allocPrint(arena, "no path restriction at all: {s}", .{m.seatbelt.why()}),
        .why = "the paths a tool call may open are named by the kernel itself, and a descriptor it never opened is no way in",
        .fix = if (m.seatbelt == .ok) "" else "sandbox_init is in libSystem on every macOS. A refusal here is a fault in Chock's own " ++
            "profile, not a setting, so it is worth reporting.",
        .blocks = true,
    });

    // The network, the signals and the IPC ride on the same profile the row
    // above measured, so they carry its state rather than a second answer
    // nobody asked for. Saying `OK` for these while `seatbelt` is off would be
    // three claims resting on a layer that is not there.
    try rows.append(arena, .{
        .name = "network",
        .state = m.seatbelt.state(),
        .means = if (m.seatbelt == .ok) "" else "the profile that closes it did not go on",
        .why = "a tool call reaches no host, and no unix socket on this machine either",
        .blocks = true,
    });
    try rows.append(arena, .{
        .name = "signal reach",
        .state = m.seatbelt.state(),
        .means = if (m.seatbelt == .ok) "" else "the profile that closes it did not go on",
        .why = "a tool call can signal its own processes and no other process you own",
        .blocks = true,
    });
    try rows.append(arena, .{
        .name = "ipc",
        .state = m.seatbelt.state(),
        .means = if (m.seatbelt == .ok) "" else "the profile that closes it did not go on",
        .why = "shared memory and message queues do not cross the boundary",
        .blocks = true,
    });

    try rows.append(arena, .{
        .name = "rlimit floor",
        .state = m.rlimits.state(),
        .means = if (m.rlimits == .ok)
            "cpu time, size of one file and open files"
        else
            try std.fmt.allocPrint(arena, "no bound on what a tool call takes: {s}", .{m.rlimits.why()}),
        .why = "a runaway tool call is ended by the kernel rather than by a person watching it",
        .blocks = true,
    });

    // The four limits with no Darwin mechanism, one row each. Every sentence
    // holds the measurement from `lib/chock-sandbox/darwin/limits.zig`, so a
    // person reads what was tried and not only what is missing.
    try rows.append(arena, .{
        .name = "memory ceiling",
        .state = .unsupported,
        .means = "macos has no cgroup, so nothing bounds how much memory a tool call takes",
    });
    try rows.append(arena, .{
        .name = "mapped memory",
        .state = .unsupported,
        .means = "setrlimit answers EINVAL for both RLIMIT_AS and RLIMIT_DATA, and a 512 MiB mapping still succeeded",
    });
    try rows.append(arena, .{
        .name = "process count",
        .state = .unsupported,
        .means = "RLIMIT_NPROC counts every process of the user, not this sandbox, so setting it would bound you and not the agent",
    });
    try rows.append(arena, .{
        .name = "disk cap tmpfs",
        .state = .unsupported,
        .means = "an ordinary user on macos cannot mount a filesystem, so there is no capped writable area to give",
    });

    try rows.append(arena, .{
        .name = "syscall filter",
        .state = .unsupported,
        .means = "a per call denial compiles and applies and does nothing: ptrace still returned 0. " ++
            "The only form with any effect stops execve as well",
    });
    try rows.append(arena, .{
        .name = "process list",
        .state = .unsupported,
        .means = "a tool call reads the whole host process table through sysctl, and taking that away stops ordinary software starting. " ++
            "It can act on none of them: see the signal reach row",
    });
    try rows.append(arena, .{
        .name = "workspace mount",
        .state = .unsupported,
        .means = "macos has no bind mount, so the workspace cannot appear at the project's own path. " ++
            "It appears at its own, and a tool call works there",
        .fix = "This gap is permanent. An absolute path a tool call writes into a file " ++
            "names the workspace, which is deleted when the session ends.",
    });

    try rows.append(arena, toolCallRow(m));
}

/// Whether a whole tool call can run on this build.
///
/// **The row that decides the exit code on a Seatbelt build.** Every layer
/// above it can be on and a session still start nothing, because a tool call is
/// assembled from more than the workspace: `chock-core` adds its own scratch
/// area, its cache and its tool directory, and each of those asks for a path to
/// appear somewhere else. So this row is measured against the driver's own
/// `expressibleOn`, with the config a real session would hand it, rather than
/// worked out from the rows above.
fn toolCallRow(m: Measured) Row {
    if (m.tool_call_refused) |why| return .{
        .name = tool_call_name,
        .state = .unavailable,
        .means = why,
        .fix = "Every layer above is on. What is missing is that a tool call still asks for a path to appear " ++
            "somewhere else, and Sandbox.spawn refuses rather than run one unprotected.",
        .blocks = true,
    };
    return .{
        .name = tool_call_name,
        .state = .on,
        .means = "",
        .why = "a tool call really runs here, inside the profile every row above measured",
    };
}

/// What every required sink row is called. One name for all of them, so
/// `isFirstRunRow` needs no list of paths and a bundle that requires three
/// sinks reads as three rows of one kind.
pub const required_sink_name = "audit sink";

/// One sink this installation requires.
///
/// **Never blocking, and that is a decision and not an oversight.** A machine
/// that cannot reach its audit sink still runs sessions, and
/// `lib/chock-policy/org.zig` weighed the alternative and refused it: a doctor
/// that exited 2 here would put the refuse-to-start answer back through the
/// back door. Refusing to start turns an organisation's control into an
/// outage, and a developer who cannot work reaches for a tool that is not
/// Chock, so the organisation gets **no** record of that work rather than a
/// late one. The session runs, the log on disk keeps every line the sink
/// missed, and a gap that is still open at the end is `Exit.audit_gap`.
///
/// So the worst this row makes the whole report is `degraded`, and the meaning
/// says both halves out loud: the session runs, and what it costs when the gap
/// stays open.
fn requiredSinkRow(arena: std.mem.Allocator, one: SinkProbe) std.mem.Allocator.Error!Row {
    const what = switch (one.kind) {
        .directory => "directory",
        .syslog => "syslog socket",
    };
    if (one.reached == .ok) return .{
        .name = required_sink_name,
        .state = .on,
        .means = try std.fmt.allocPrint(
            arena,
            "this installation requires the {s} {s}, and it was reached",
            .{ what, one.path },
        ),
    };
    return .{
        .name = required_sink_name,
        .state = one.reached.state(),
        .means = try std.fmt.allocPrint(
            arena,
            "this installation requires the {s} {s}, and it could not be reached: {s}. " ++
                "A session still starts and the log keeps every line the sink missed, and it " ++
                "exits {d} when that tail is still on this machine at the end",
            .{ what, one.path, one.reached.why(), Exit.audit_gap.code() },
        ),
        // **The installation and never a flag.** Nobody at this keyboard asked
        // for this sink, so a reader sent to a command line would look through
        // one that does not hold it.
        .fix = "Nobody typed this sink: an org policy bundle requires it. Start the collector " ++
            "that reads it, or ask whoever installed this Chock.",
        .blocks = false,
    };
}

/// The cgroup row. **Degraded and never blocking**, which is
/// `chock-sandbox/linux/cgroup.zig`'s own decision: a machine with no cgroup
/// v2 tree still gets the rlimit floor, and a sandbox must not rearrange the
/// machine it runs on to protect one tool call.
fn cgroupRow(
    arena: std.mem.Allocator,
    support: ?CgroupSupport,
    vantage: ?CgroupVantage,
) std.mem.Allocator.Error!Row {
    const found = support orelse return .{
        .name = "cgroup v2",
        .state = .unsupported,
        .means = "no memory or process bound was asked for: " ++ driver_gives_nothing,
    };
    const view = vantageNote(vantage);
    return .{
        .name = "cgroup v2",
        // **`supplied` cannot come from the measurement this row reads.**
        // `cgroupRow` is given what `cgroup.Cgroup.create` answered, and that
        // call makes chock's own cgroup and never takes one from a caller. The
        // arm is here so the switch stays exhaustive, and it reads `on`
        // because a supplied cgroup really does hold the program. The sentence
        // beside it says who wrote the numbers in it.
        .state = switch (found) {
            .ok, .supplied => .on,
            .off => .off,
            .unsupported => .unsupported,
            .unavailable => .unavailable,
        },
        .means = switch (found) {
            .ok => "",
            else => try std.fmt.allocPrint(arena, "{f}. The rlimit floor still applies{s}", .{ found, view.means }),
        },
        .why = "the memory and pids controllers are delegated, so a tool call has a resident memory bound and a process count bound",
        .fix = switch (found) {
            .ok, .off, .supplied => "",
            .unsupported, .unavailable => view.fix orelse fixFor(found),
        },
        .blocks = false,
    };
}

/// What every fix on this row starts with. The controllers are named by the
/// library's own reason text, so this file states no second copy of the list.
const cgroup_floor = "A tool call still gets the rlimit floor, so a session runs. What it loses is the " ++
    "resident memory bound and the per sandbox process count. ";

/// What a row that is not on adds, and what it tells a person to do, once the
/// vantage is known.
const VantageNote = struct {
    /// What the row says after the reason. Empty for an answer about this
    /// machine, which needs no second sentence.
    means: []const u8,
    /// What to do, when the vantage alone decides it. Null when the answer's
    /// own reason decides it, which `fixFor` reads.
    fix: ?[]const u8,
};

/// The sentences for one vantage.
///
/// **A refusal measured from inside a namespace is not a refusal by the
/// machine, and the two need different words.** `chock doctor` exists to say
/// whether a session can run, and the old row said "ask your init system to
/// delegate" for a machine whose init system already delegates. Somebody then
/// reads a kernel that works. See `cgroup.Vantage` for what a cgroup namespace
/// does to the path the answer is derived from.
fn vantageNote(vantage: ?CgroupVantage) VantageNote {
    const ask_here = cgroup_floor ++ "This chock is inside the container, so the controllers have to be " ++
        "delegated there. Run chock doctor outside it to measure the machine itself.";

    const known = vantage orelse return .{ .means = "", .fix = null };
    return switch (known) {
        .own, .none => .{ .means = "", .fix = null },
        .foreign => .{
            .means = ". This process is in a cgroup namespace, so that is the answer for the " ++
                "cgroup tree it can see and not for the machine outside it",
            .fix = ask_here,
        },
        .not_mounted => .{
            .means = ". The kernel has a cgroup v2 hierarchy and this process can see no tree " ++
                "mounted, so that is the answer for this view and not for the machine outside it",
            .fix = ask_here,
        },
        .unknown => .{
            .means = ". Which cgroup holds this process could not be read, so the answer may be " ++
                "for its own view and not for the machine",
            .fix = null,
        },
    };
}

/// What to do about an answer that was measured on this machine's own tree.
///
/// **`create_refused` is not a machine that delegates nothing.**
/// `cgroup.Support.Reason` only answers it after an ancestor was found that
/// already lists every controller, and `mkdirat` was refused under every one
/// of them. Measured on 2026-08-24 on a systemd box: of the cgroups above a
/// user's own, only `user@1000.service` is owned by that user, so a chock
/// started outside their user manager finds the delegation and may not write
/// there. Telling that person to ask for delegation is advice for a fault
/// they do not have.
fn fixFor(found: CgroupSupport) []const u8 {
    const ask_init = cgroup_floor ++ "Ask the machine's init system to delegate the controllers to your user slice.";
    const ask_where = cgroup_floor ++ "The controllers are already delegated above this process and no directory " ++
        "could be made under them, so this is about which cgroup chock was started in. Start it from a session " ++
        "your own user manager owns.";

    return switch (found) {
        // A supplied cgroup names nothing to fix on this machine: the caller
        // made it and the caller holds it. See `cgroupRow` for why this row
        // never reads that answer at all.
        .ok, .off, .supplied => "",
        .unsupported, .unavailable => |reason| switch (reason) {
            .no_cgroup2_tree,
            .no_cgroup2_mount,
            .not_in_unified_hierarchy,
            .cgroup_path_too_long,
            .no_delegated_parent,
            .write_refused,
            => ask_init,
            .create_refused => ask_where,
        },
    };
}

/// Whether this machine has `git`.
///
/// **It blocks, and the report had no row for it at all.** Every session
/// builds a workspace, and a worktree is what a workspace is on a project with
/// git of its own. Measured on 2026-08-25 on a machine with no git: `chock run`
/// answered "the workspace for /proj could not be built: NotFound", which
/// names neither git nor anything a person could act on.
fn gitRow(m: Measured) Row {
    if (m.git_program) |path| return .{
        .name = "git",
        .state = .on,
        .means = path,
        .why = "the session works in a worktree of your project, so your own tree is never edited",
    };
    return .{
        .name = "git",
        // `unavailable` and not `off`: `off` is a layer this session gave up,
        // and a machine with no git is a machine somebody can install git on.
        // The word beside it reads `BLOCKED` because the row stops a first
        // run, which `wordFor` reads from `blocks` and not from here.
        .state = .unavailable,
        .means = "not on this machine's PATH, so no session can build a workspace and no session can start",
        .fix = "Install git. Chock runs it to make the worktree a session works in and to apply the work back.",
        .blocks = true,
    };
}

fn nixRow(m: Measured) Row {
    if (m.nix_program) |path| return .{
        .name = "nix",
        .state = .on,
        .means = path,
    };
    return .{
        .name = "nix",
        .state = .off,
        .means = "not on this machine's PATH, so a project's dev shell cannot be read and no program can be provisioned",
        .fix = "Only a project with a flake.nix needs it. Install nix, or run chock from a shell that has it.",
        .blocks = false,
    };
}

fn devShellRow(arena: std.mem.Allocator, state: DevShellState) std.mem.Allocator.Error!Row {
    return switch (state) {
        .no_flake => .{
            .name = "dev shell",
            .state = .off,
            // **What a session really mounts is the toolchain row's to say.**
            // This used to end "and the sandbox mounts the whole Nix store",
            // which is false on a machine with no Nix store, and it was
            // printed on the very machine where every tool call then died in
            // the mount tree.
            .means = "this project states no flake.nix, so tool calls do not get a toolchain of the project's own",
            .fix = "Write a flake.nix with a dev shell to narrow what a session mounts.",
        },
        .read => |evaluated| .{
            .name = "dev shell",
            .state = .on,
            // Which of the two is a measurement: an evaluation took seconds and
            // a cache read took none.
            .means = if (evaluated) "evaluated with nix" else "read from the cache",
            .why = "every tool call gets this project's own toolchain",
        },
        .failed => |reason| .{
            .name = "dev shell",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "nix could not read it: {s}", .{reason}),
            // Stated rather than blocking, and this is `src/run.zig`'s own
            // rule: a broken flake is often the very thing somebody starts a
            // session to fix, and refusing would leave them with no agent and
            // a broken flake instead of one of the two.
            .fix = "A session still runs. The toolchain row says what it mounts instead.",
        },
        .no_nix => .{
            .name = "dev shell",
            .state = .unavailable,
            .means = "this project has a flake.nix and this machine has no nix to read it with",
            .fix = "A session still runs on the host toolchain. Install nix to get this project's own.",
        },
    };
}

/// What a container runtime on this machine answered, or null when this
/// machine needs no row.
///
/// **A machine that needs no runtime gains no row**, the same rule an
/// installation with no policy bundle already gets for its audit sinks. Most
/// machines have no container runtime and most projects name no image, and a
/// yellow row about a thing nobody asked for teaches a person to stop reading
/// the report. So a row appears when a runtime really answered, which is a
/// fact worth stating, or when the project names an image, which is when a
/// runtime that is absent or silent matters.
fn containerRow(
    arena: std.mem.Allocator,
    state: ContainerState,
    toolchain: ToolchainState,
) std.mem.Allocator.Error!?Row {
    const wanted = switch (toolchain) {
        .image, .image_unusable => true,
        .dev_shell, .host, .none => false,
    };

    return switch (state) {
        .not_installed => if (!wanted) null else .{
            .name = "container runtime",
            .state = .off,
            .means = "none is on this machine's PATH, and this project names a container image",
            .fix = "Install podman, which needs no daemon and unpacks an image with your own " ++
                "privilege, or install docker, whose daemon runs as root by default.",
        },
        .unreachable_runtime => |text| if (!wanted) null else .{
            .name = "container runtime",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "it is installed and did not answer: {s}", .{text}),
            // Stated and not blocking. The toolchain row carries the refusal,
            // because that is the row that says a session cannot start.
            .fix = "Start the runtime's daemon, or install podman, which has none.",
        },
        .ready => |ready| .{
            .name = "container runtime",
            .state = .on,
            .means = try std.fmt.allocPrint(arena, "{s}", .{ready.kind.displayName()}),
            .why = "a project with no Nix can name a container image, and its files become the toolchain",
            // **The trust position is its own line and never a state.** A
            // caller that reads this row as a layer would be reading a fact
            // about who unpacked a file as a fact about the sandbox, and the
            // sandbox is unchanged either way.
            .fix = if (ready.trust.isPrivileged())
                try std.fmt.allocPrint(
                    arena,
                    "Warning: {s}. The sandbox a tool call runs in is unchanged. Podman rootless " ++
                        "is the stronger position.",
                    .{ready.trust.text()},
                )
            else
                "",
        },
    };
}

/// Where the files a tool call would run come from.
///
/// **The row that makes a first run honest.** Every other row of this report
/// can pass on a machine where no tool call can work: the sandbox is whole,
/// the credential is there, and there is nothing to mount. See
/// `ToolchainState` for the measurement that produced this row.
fn toolchainRow(arena: std.mem.Allocator, state: ToolchainState) std.mem.Allocator.Error!Row {
    return switch (state) {
        .dev_shell => .{
            .name = "toolchain",
            .state = .on,
            .means = "this project's own dev shell",
            .why = "a tool call runs the project's own programs and the sandbox mounts that closure and no more",
        },
        .image => |reference| .{
            .name = "toolchain",
            .state = .on,
            .means = try std.fmt.allocPrint(arena, "the image {s}, already on this machine", .{reference}),
            .why = "a tool call runs the image's own programs. The image is a source of files and " ++
                "nothing runs in a container",
        },
        .image_unusable => |why| .{
            .name = "toolchain",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "no session can start: {s}", .{why}),
            // **The sentence a person acts on is in `means`**, because it
            // differs: an image nobody pulled, a runtime that is not there,
            // and a block that does not parse are three different repairs.
            // This line says the one thing that is true of all three.
            .fix = "Chock reads the image before the session starts and never during one, because " ++
                "a tool call has no network and no daemon socket.",
            .blocks = true,
        },
        .host => |count| .{
            .name = "toolchain",
            .state = .on,
            .means = try std.fmt.allocPrint(
                arena,
                "this machine's own programs, with {d} system directories mounted read only",
                .{count},
            ),
            .why = "a tool call can run what this machine has",
            // Not a fault and worth a line every time, because it is the
            // widest of the three answers and the person may not know they
            // are on it.
            .fix = "This is the widest answer. Narrow it with a flake.nix dev shell, or with " ++
                ".container = .{ .image = \"...\" } in chock.zon.",
        },
        .none => .{
            .name = "toolchain",
            .state = .unavailable,
            .means = "no session can start: there is nothing for a tool call to run a program from",
            .fix = "This project states no dev shell and no container image, and none of the usual " ++
                "system directories is on this machine either. Give the project a flake.nix with a " ++
                "dev shell, or a chock.zon holding .container = .{ .image = \"...\" }.",
            .blocks = true,
        },
    };
}

fn credentialRow(arena: std.mem.Allocator, state: CredentialState) std.mem.Allocator.Error!Row {
    return switch (state) {
        .found => |source| .{
            .name = "credential",
            .state = .on,
            .means = try std.fmt.allocPrint(arena, "found: {s}", .{source}),
        },
        // Not an error and not a gap. A local endpoint asks for nothing, and
        // `chock_auth.lookup.Source.none` is how that is said.
        .not_needed => .{
            .name = "credential",
            .state = .off,
            .means = "this provider asks for none, which is what a local endpoint is",
        },
        // A gap, and it blocks. `chock run` refuses this one before it builds
        // anything, so the report and the command agree.
        .missing => |reason| .{
            .name = "credential",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "no session can be started: {s}", .{reason}),
            .fix = "Run chock login for this provider instance.",
            .blocks = true,
        },
        .unconfigured => |reason| .{
            .name = "credential",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "no session can be started: {s}", .{reason}),
            .fix = "Write a provider and a model into config.zon, then run chock login.",
            .blocks = true,
        },
        .unreadable => |reason| .{
            .name = "credential",
            .state = .unavailable,
            .means = try std.fmt.allocPrint(arena, "the credential could not be read: {s}", .{reason}),
            .fix = "Run chock login for this provider instance.",
            .blocks = true,
        },
    };
}

fn cacheRow(arena: std.mem.Allocator, probe: Probe) std.mem.Allocator.Error!Row {
    return .{
        .name = "toolchain cache",
        .state = probe.state(),
        .means = if (probe == .ok)
            ""
        else
            try std.fmt.allocPrint(arena, "it could not be made: {s}", .{probe.why()}),
        .why = "the directory a compiler writes into is there and writable",
        // A warning in `src/run.zig` and not a refusal, so it is one here too.
        .fix = if (probe == .ok) "" else "A session still runs. A compiler in it has nowhere but the workspace to write, " ++
            "so every session recompiles from nothing.",
        .blocks = false,
    };
}

/// What `chock sessions seal` can sign a log's chain head with.
///
/// **Never blocking.** `seal.Level` has three values and the third is a
/// software key, so a machine with no reader signs and records that it used the
/// weaker key. A doctor that exited 2 here would refuse to start a session over
/// a fallback the design already made and already records.
///
/// The three states are the ones `Probe` already has, and they mean here what
/// they mean everywhere else in this report: `unsupported` is a machine with
/// nothing to configure, `unavailable` is a machine that has the thing and
/// would not let this process use it.
fn cardSealRow(
    arena: std.mem.Allocator,
    probe: Probe,
    readers: ?usize,
) std.mem.Allocator.Error!Row {
    return .{
        .name = "card seal",
        .state = probe.state(),
        .means = if (probe == .ok) try std.fmt.allocPrint(
            arena,
            // **The reader count and not a card.** Whether a card is in the
            // reader is not read here: finding out means connecting to it, and
            // a report must not take a reader another program is using.
            "a PC/SC daemon answered and named {d} reader(s)",
            .{readers orelse 0},
        ) else try std.fmt.allocPrint(arena, "no card key on this machine: {s}", .{probe.why()}),
        .why = "a card key can be tried, so a seal can reach level 2 or level 1",
        .fix = if (probe == .ok) "" else "A session still runs and `chock sessions seal` still signs, with a software key, " ++
            "and the level it used is inside the bytes the signature covers.",
        .blocks = false,
    };
}

fn freeSpaceRow(arena: std.mem.Allocator, free: ?u64) std.mem.Allocator.Error!Row {
    const floor = chock_core.tools.default_workspace_free_floor_bytes;
    const bytes = free orelse return .{
        .name = "workspace space",
        .state = .unavailable,
        // Never read as a full disk. The same rule `chock_io.Io.freeBytes`
        // keeps: an unreadable filesystem is not an empty one, and a caller
        // that read the two the same way would refuse every call.
        .means = "the free space could not be read, which is not the same as no room",
        .fix = "A session still runs. A writing tool call is refused only when the reading works and answers too little.",
        .blocks = false,
    };
    if (bytes >= floor) return .{
        .name = "workspace space",
        .state = .on,
        .means = try std.fmt.allocPrint(arena, "{d} MiB free, over the {d} MiB floor", .{
            bytes / (1024 * 1024),
            floor / (1024 * 1024),
        }),
    };
    return .{
        .name = "workspace space",
        .state = .unavailable,
        .means = try std.fmt.allocPrint(arena, "{d} MiB free, under the {d} MiB floor", .{
            bytes / (1024 * 1024),
            floor / (1024 * 1024),
        }),
        .fix = "Every writing tool call is refused under the floor, so a session starts and gets nothing done. Free some space.",
        // A session that can write nothing is a first run that fails.
        .blocks = true,
    };
}

/// How wide the name column is, as `printRow`'s own format string spells it.
/// Wide enough for the longest name above; a name that overflows this pushes
/// its own sentence out of the column and makes the whole report read as
/// ragged.
const name_width = 17;

/// Print the report on standard output, and the refusal, when there is one,
/// on standard error.
///
/// **The rows are the answer a person asked for, so they go to standard
/// output.** The one line that says a machine cannot run a session is a
/// diagnostic, so it goes to standard error, which is the rule the rest of
/// this program keeps.
fn printReport(project_root: []const u8, m: Measured, rows: []const Row, verdict: Verdict) void {
    // **The build, on the first line, on every run.** This is the report a
    // person pastes into a bug, and it is worth more here than `chock
    // --version` is: nobody runs that before reporting a fault, and everybody
    // runs this. One line that answers "which Chock" is an answer and not a
    // teaching, so it is not held back for `--verbose` the way the rationale
    // rows are.
    tty.out(.plain, "{s}\n", .{version_line});

    // **The project is a `--verbose` line.** A person who typed the command in
    // a directory knows which directory they typed it in, and `--project` is
    // read back from the command line they typed. It is still here for a report
    // pasted into a bug, which is what `--verbose` is for.
    tty.detail("{s}\n", .{project_root});
    tty.out(.plain, "\n", .{});

    if (m.family == .none) {
        // The one sentence. Never a column of layers: see `refuses_outright`.
        tty.print(.err, "{s}\n\n", .{refuses_outright});
    } else {
        tty.out(.plain, "{s}\n", .{layers_heading});
        for (rows) |row| {
            if (isFirstRunRow(row)) continue;
            printRow(row);
        }
        tty.out(.plain, "\n", .{});
    }

    tty.out(.plain, "{s}\n", .{first_run_heading});
    for (rows) |row| {
        if (!isFirstRunRow(row)) continue;
        printRow(row);
    }
    tty.out(.plain, "\n", .{});

    // **A sentence and never a row.** Redaction has nothing to measure here:
    // no state a machine can be in, no fix, and no answer that differs from
    // one box to the next. A row would carry a glyph and a word over a
    // measurement nobody took, which is the fault this whole command exists to
    // avoid, and it would read as a layer somebody could turn on.
    //
    // **Printed byte for byte**, and never a summary of it.
    // `chock_core.redact.not_a_boundary` is held beside the mechanism for
    // exactly this: a command that shows it to a person must show the words
    // that module argued for, and not a paraphrase that got friendlier.
    if (tty.verbose()) tty.out(.plain, "{s}\n\n", .{chock_core.redact.not_a_boundary});

    switch (verdict) {
        .ready => tty.out(.plain, "chock doctor: a session can start here, with every row on.\n", .{}),
        // The counts read as "{d} of {d}" rather than as a sentence with a
        // verb in it, because a sentence that says "1 rows" reads as a bug in
        // the report and makes a person doubt the rest of it.
        .degraded => tty.out(
            .plain,
            "chock doctor: a session can start here. Rows that are not on: {d} of {d}. None of them stops a first run.\n",
            .{ countNotOn(rows), rows.len },
        ),
        .blocked => tty.print(
            .err,
            "chock doctor: a session cannot start here. Rows that stop a first run: {d} of {d}.\n",
            .{ countBlocking(rows), rows.len },
        ),
    }
}

/// Whether a row belongs under `first_run_heading` rather than under
/// `layers_heading`. Read from the name, so the two loops above and the order
/// in `rowsFor` can never disagree about which half a row is in.
fn isFirstRunRow(row: Row) bool {
    for ([_][]const u8{
        "git",
        "nix",
        "dev shell",
        "container runtime",
        "toolchain",
        "credential",
        "toolchain cache",
        "workspace space",
        "card seal",
        required_sink_name,
    }) |name| {
        if (std.mem.eql(u8, row.name, name)) return true;
    }
    return false;
}

/// One row, and what a person needs to read it.
///
/// **A row that is on is a glyph, a name and a word.** The sentence that says
/// what the layer gives is the same on every machine and on every run, so it is
/// a lesson and not an answer: it waits for `--verbose`. A number the machine
/// really gave stays, because that differs from one box to the next.
///
/// **A row that is not on keeps every word it had.** What is lost is in
/// `means` and what to do is in `fix`, and neither of those is decoration. That
/// is the whole reason this report is worth running.
fn printRow(row: Row) void {
    // The glyph and the word both, and never colour alone. No fact may rest on
    // colour, and this report is read in a pipe more often than on a screen.
    //
    // A row with nothing to report stops after the word. Padding the word out
    // to its column and then writing nothing would leave trailing blanks on
    // most lines of the report, which `grep` and a diff both read as content.
    if (row.means.len == 0) {
        tty.out(.plain, "  {s} {s: <17}  {s}\n", .{
            row.state.glyph(),
            row.name,
            wordFor(row),
        });
    } else {
        tty.out(.plain, "  {s} {s: <17}  {s: <8}  {s}\n", .{
            row.state.glyph(),
            row.name,
            wordFor(row),
            row.means,
        });
    }
    if (row.state == .on and row.why.len != 0 and tty.verbose()) {
        tty.out(.dim, "      {s}\n", .{row.why});
    }
    if (row.fix.len != 0) tty.out(.plain, "      {s}\n", .{row.fix});
}

fn countNotOn(rows: []const Row) usize {
    var count: usize = 0;
    for (rows) |row| {
        if (row.state != .on) count += 1;
    }
    return count;
}

fn countBlocking(rows: []const Row) usize {
    var count: usize = 0;
    for (rows) |row| {
        if (row.state != .on and row.blocks) count += 1;
    }
    return count;
}

/// Read this machine.
///
/// **A build whose driver applies no layer measures no layer.** It does not
/// ask a kernel about a mechanism its own driver would never reach, which is
/// the difference between a measurement and a guess. The host half below is
/// measured either way, because it is true of the machine whatever the driver
/// does with it.
fn measure(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) Measured {
    var m = Measured{};
    // **Comptime, so a branch this build's driver never takes is never
    // analysed.** `measureLayers` names Linux mechanisms and `measureSeatbelt`
    // names Darwin ones, and neither compiles for the other target.
    switch (comptime LayerFamily.forDriver(sandbox.Sandbox.guarantees)) {
        .none => {},
        .namespaces => measureLayers(arena, io, env, project_root, &m),
        .seatbelt => measureSeatbelt(arena, io, env, project_root, &m),
    }
    measureHost(arena, gpa, io, env, project_root, &m);
    return m;
}

fn measureHost(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    m: *Measured,
) void {
    m.git_program = chock_nix.proc.resolve(arena, io, env, "git") catch null;
    m.nix_program = chock_nix.proc.resolve(arena, io, env, "nix") catch null;
    m.dev_shell = measureDevShell(arena, gpa, io, env, project_root, m.nix_program != null);
    m.container = measureContainer(arena, io, env);
    m.toolchain = measureToolchain(arena, io, env, project_root, m.dev_shell, m.container);
    m.credential = measureCredential(arena, io, env);

    m.cache = cache: {
        const dir = session_paths.cacheDir(arena, env, project_root) catch |err| break :cache .{
            .refused = @errorName(err),
        };
        _ = session_paths.createCacheDir(io, dir, null) catch |err| break :cache .{ .refused = @errorName(err) };
        break :cache .ok;
    };

    // The filesystem the workspace will live on, which is not the project's
    // own: a workspace is built under Chock's state directory. The deepest
    // ancestor that exists is what is read, because `freeBytes` answers null
    // for a path that is not there and a project that has never run a session
    // has no directory of its own yet.
    if (session_paths.projectDir(arena, env, project_root) catch null) |dir| {
        m.free_bytes = freeBytesNear(dir);
    }

    measureCardSeal(arena, io, m);

    m.required_sinks = measureRequiredSinks(arena, io, env);

    m.write_execute = measureHardening(arena, io, env, project_root, defaultModel(arena, io, env));
}

/// Whether a session of this project would run with the write and execute rule
/// off. **The one sandbox row that is a question about the project and not
/// about the machine**: every machine this driver runs on can hold the rule,
/// and `chock_policy.hardening` is the row a project writes to give it up.
///
/// **The org bundle is read first, and leaving it out would be a lie in the
/// dangerous direction.** A rule in the bundle can only lower the answer, so a
/// report that read only `chock.zon` would say a session gives up hardening
/// that the organisation has already forbidden. The same rules, in the same
/// order, that `src/run.zig` folds.
///
/// **This asks the question the way a root session asks it**: the agent kind
/// `chock run` starts with, and the model the configuration names by default,
/// which together are what a `chock run` with no flags carries. A project whose
/// rule names another agent kind, or a model the command line would have to
/// pick, reads `strict` here and is answered by the session itself. That is the
/// safe direction: this row never says the hardening is off when it is on.
///
/// A `chock.zon` this cannot read answers `strict`, which is what a session
/// gets too: `chock run` refuses to start on a policy it cannot parse.
fn measureHardening(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    model: []const u8,
) chock_policy.hardening.WriteExecute {
    const org_rules: []const chock_policy.table.Rule = rules: {
        const data_dir = chock_auth.paths.dataDir(arena, env) catch break :rules &.{};
        const path = std.fs.path.join(arena, &.{ data_dir, chock_policy.org.file_name }) catch
            break :rules &.{};
        const bundle = chock_policy.org.load(arena, io, path, null) catch break :rules &.{};
        break :rules bundle.rules;
    };

    const policy = chock_policy.table.Table.loadUnder(
        arena,
        io,
        project_root,
        org_rules,
        null,
    ) catch return .strict;

    return chock_policy.hardening.writeExecuteFor(policy.evaluateChain(&.{doctor_agent_kind}, .{
        .agent_kind = doctor_agent_kind,
        .model = model,
        // No tool call asked for this and none ever can: the filter is built
        // before the first turn. See `chock_broker.actions.self_asked_tool`.
        .tool = chock_broker.actions.self_asked_tool,
        .action = chock_policy.hardening.jit_action,
    }, null));
}

/// The agent kind this command asks the policy about. `chock run`'s own
/// default, so the answer here is the answer a session started with no
/// `--agent-kind` gets.
const doctor_agent_kind = "main";

/// The model this command asks the policy about when the configuration names
/// no default. **A name no provider issues**, because `table.Key` refuses an
/// empty model and any real spelling here could match a rule an author wrote
/// for a real model. It matches only a rule that names no model at all, which
/// is the reading that keeps the hardening.
const no_default_model = "(no default model)";

/// The model a `chock run` with no `--model` would use, or `no_default_model`
/// when this machine has no configuration to read one from. **The same reader
/// `measureCredential` uses**, so the two rows cannot disagree about what the
/// configuration says.
fn defaultModel(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) []const u8 {
    const config_dir = chock_auth.paths.configDir(arena, env) catch return no_default_model;
    const config = chock_auth.config.load(arena, io, config_dir, null) catch return no_default_model;
    const named = config.default_model orelse return no_default_model;
    return if (named.len == 0) no_default_model else named;
}

/// Reach for a PC/SC daemon with the transport `chock sessions seal` uses.
///
/// **A platform with no transport measures nothing.** On Darwin the driver
/// answers `error.Unavailable` for every call, and asking it would produce a
/// row that says the machine is missing something an administrator could
/// install. It is the build that is missing it.
fn measureCardSeal(arena: std.mem.Allocator, io: std.Io, m: *Measured) void {
    if (comptime !@hasDecl(chock_pcsc.platform, "Failure")) {
        m.card_seal = .{ .absent = "this build has no PC/SC transport: macOS reaches a card " ++
            "through a framework that has to be linked, and Chock links no platform library" };
        return;
    } else {
        var driver = chock_pcsc.default(io);
        defer driver.deinit();

        driver.establish() catch |err| {
            // The driver's own sentence, which carries the two version numbers
            // and the socket path an error name cannot. Only the error name
            // when there is somehow no sentence, so a row is never empty.
            const why = if (driver.failure) |failure|
                std.fmt.allocPrint(arena, "{f}", .{failure}) catch @errorName(err)
            else
                @errorName(err);
            m.card_seal = switch (err) {
                // **A daemon that is there and said no.** An administrator can
                // change a polkit rule, which is what `unavailable` means in
                // every other row of this report. A protocol this build does
                // not speak is the same shape of answer: the machine has the
                // daemon and this build cannot use it.
                error.NotAuthorized, error.ProtocolMismatch => .{ .refused = why },
                // No socket, no listener, or a transport that failed. There is
                // nothing here to permit.
                else => .{ .absent = why },
            };
            return;
        };

        var names: [4096]u8 = undefined;
        const written = driver.pcsc().listReaders(&names) catch |err| {
            m.card_seal = .{ .absent = @errorName(err) };
            return;
        };

        var list = chock_pcsc.ReaderList.init(names[0..written]);
        var counted: usize = 0;
        while (list.next()) |_| counted += 1;
        m.card_readers = counted;

        // **A daemon with no reader is not a daemon that refused.** Nothing is
        // wrong with the machine and nothing can be configured: somebody has to
        // plug a reader in, which is what `absent` says.
        m.card_seal = if (counted == 0)
            .{ .absent = "a PC/SC daemon answered and no reader is attached" }
        else
            .ok;
    }
}

/// What the probe file inside a required drop directory is called.
///
/// **Not a `.jsonl`, and it starts with a dot.** A collector watches that
/// directory for the one file a session leaves, which is `<session>.jsonl`, and
/// a probe that looked like a session's own drop would be picked up as an empty
/// session. This one is removed before the command returns whatever happens,
/// and it is named so that a file somebody finds after a crash says what made
/// it.
///
/// **A constant name, unlike the probe tree beside it, and that is measured
/// rather than assumed.** An organisation names one drop directory for every
/// project, so two `chock doctor` runs do meet in it. Neither can spoil the
/// other: the probe is `FileDrop.reach`, which creates the file and reads its
/// length through the descriptor, so a second run that removes the file
/// changes nothing either run reads, and both report the sink as reached. The
/// constant name is what makes the file a crash left get removed by the next
/// run, which a name of one run's own would end. See `probeDirName` for the
/// tree, where a second run really did spoil the first one's measurement.
const probe_drop_name = ".chock-doctor.probe";

/// Reach for every sink this installation's org policy bundle requires.
///
/// **Doctor reads the bundle itself**, out of the data directory
/// `lib/chock-auth/paths.zig` names, which is the same file `chock run` reads
/// and the same reader. A session is not started to find out.
///
/// **An installation with no bundle measures nothing and gains no row.** So
/// does one whose bundle cannot be read: that file makes `chock run` refuse
/// with the bundle reader's own diagnostic, which names the line and the
/// reason, and a row here would be a second, shorter answer to keep true. What
/// this command has to add is the part no reader can know, which is whether the
/// machine can reach the places the bundle names.
fn measureRequiredSinks(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) []const SinkProbe {
    const data_dir = chock_auth.paths.dataDir(arena, env) catch return &.{};
    const path = std.fs.path.join(arena, &.{ data_dir, chock_policy.org.file_name }) catch return &.{};
    const bundle = chock_policy.org.load(arena, io, path, null) catch return &.{};
    if (bundle.sinks.len == 0) return &.{};

    const probes = arena.alloc(SinkProbe, bundle.sinks.len) catch return &.{};
    for (bundle.sinks, probes) |required, *slot| {
        slot.* = .{
            .kind = required.kind,
            .path = required.path,
            .reached = reachSink(arena, io, required),
        };
    }
    return probes;
}

/// Whether one required sink can be reached from this machine, now.
///
/// **Through `chock_proto.ship`'s own transports and nothing else.** This
/// command's rule is that a second way to ask would be a second answer to keep
/// true, so it does not make a socket, connect it, or open a drop of its own:
/// `Sink.reach` exists for this caller, and it sends nothing, so no record of a
/// probe lands in an organisation's audit trail.
fn reachSink(
    arena: std.mem.Allocator,
    io: std.Io,
    required: chock_policy.org.RequiredSink,
) Probe {
    switch (required.kind) {
        .syslog => {
            var syslog = chock_proto.ship.Syslog{ .path = required.path };
            defer syslog.close();
            syslog.sink().reach(io) catch |err| return .{ .refused = @errorName(err) };
            return .ok;
        },
        .directory => {
            // **The directory is made and never required**, which is what
            // `src/run.zig` does before it opens a drop: an operator names a
            // directory a collector will watch, and one that is not there yet
            // is not a machine that cannot reach it. A directory that could
            // not be made shows up below as a drop that could not be opened.
            //
            // **`makeDirAll` and not `std.Io.Dir.createDirPath`**, and the
            // difference is a hang. `createDirPath` walks back to a component
            // it can make and then walks forward again, so a directory whose
            // creation answers `ENOENT` while its parent exists sends it
            // between the two for ever. A bundle naming a path under `/proc`
            // is exactly that, because `mkdir` there answers `ENOENT` and not
            // `EACCES`, and `chock doctor` then spun at 96 percent of a core
            // instead of reporting anything. Measured on 2026-08-24.
            // `makeDirAll` walks up once and stops.
            makeDirAll(io, required.path) catch {};
            const path = std.fs.path.join(arena, &.{ required.path, probe_drop_name }) catch
                return .{ .refused = "the probe path could not be built" };
            var drop = chock_proto.ship.FileDrop{ .path = path };
            // **Removed again, whatever happens**, and closed first. Nothing
            // this command makes may outlive it, which is the rule the probe
            // tree above keeps as well.
            defer std.Io.Dir.cwd().deleteFile(io, path) catch {};
            defer drop.close(io);
            drop.sink().reach(io) catch |err| return .{ .refused = @errorName(err) };
            return .ok;
        },
    }
}

/// Free bytes on the filesystem `path` is on, or on the filesystem of its
/// deepest ancestor that exists. Null when nothing above it could be read.
fn freeBytesNear(path: []const u8) ?u64 {
    const driver = chock_io.default();
    var here: []const u8 = path;
    // Bounded, and the bound is the path itself: every step drops one
    // component, so this ends at the root whatever it is given.
    while (here.len != 0) {
        if (driver.freeBytes(here)) |bytes| return bytes;
        here = std.fs.path.dirname(here) orelse return null;
    }
    return null;
}

fn measureDevShell(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    has_nix: bool,
) DevShellState {
    const dir = session_paths.devShellDir(arena, env, project_root) catch return .no_flake;
    session_paths.createDevShellDir(io, dir) catch return .no_flake;

    var diag: ?chock_nix.Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    // The same call a session makes, against the same cache, so a warm
    // machine answers at once and a cold one waits exactly as long as its
    // first run would.
    const loaded = chock_nix.DevShell.load(gpa, io, .{
        .project_root = project_root,
        .cache_dir = dir,
        .host_env = env,
        .diag = &diag,
    }) catch |err| {
        if (!has_nix) return .no_nix;
        if (diag) |*fault| return .{
            .failed = std.fmt.allocPrint(arena, "{f}", .{fault}) catch @errorName(err),
        };
        return .{ .failed = @errorName(err) };
    };
    var shell = loaded orelse return .no_flake;
    defer shell.deinit();
    return .{ .read = shell.evaluated };
}

/// Ask a container runtime what it is, the same way a session would.
///
/// **The same `detect` a session makes**, so this report states no second
/// answer to keep true. It runs one `info`, which is a runtime call and never
/// a fetch and never an extraction.
fn measureContainer(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) ContainerState {
    const answer = chock_container.Runtime.detect(arena, io, env, null) catch return .not_installed;
    return switch (answer) {
        .not_installed => .not_installed,
        .refused => |refusal| .{ .unreachable_runtime = refusal.text },
        .ready => |found| .{ .ready = .{
            .kind = found.kind,
            .program = found.program,
            .trust = found.trust,
        } },
    };
}

/// Where the files a tool call would run come from, decided the same way
/// `src/run.zig` decides it.
///
/// **The image half inspects and never extracts.** A report must not spend the
/// minutes a first extraction takes, and it does not have to: the question is
/// whether a session would start, and `Image.present` answers that with one
/// `image inspect`. See `chock_container.Image.present`.
///
/// **The host half asks the filesystem and never a list.** It counts the same
/// candidates `src/run.zig`'s own `hostToolchainPaths` binds, so a report and a
/// session cannot disagree about how wide the fallback is.
fn measureToolchain(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    dev_shell: DevShellState,
    container: ContainerState,
) ToolchainState {
    const named: ?[]const u8 = switch (chock_container.config.load(arena, io, project_root) catch |err| {
        return .{ .image_unusable = std.fmt.allocPrint(
            arena,
            "the container block of this project's chock.zon could not be read ({t})",
            .{err},
        ) catch "the container block of this project's chock.zon could not be read" };
    }) {
        .none => null,
        .refused => |text| return .{ .image_unusable = text },
        .named => |reference| reference,
    };

    if (named) |reference| {
        const ready = switch (container) {
            .ready => |value| value,
            .not_installed => return .{ .image_unusable = std.fmt.allocPrint(
                arena,
                "this project names the image {s} and no container runtime is installed",
                .{reference},
            ) catch "this project names an image and no container runtime is installed" },
            .unreachable_runtime => |text| return .{ .image_unusable = text },
        };

        // **The resolved path and never the bare name.** `proc.run` asserts
        // that `argv[0]` is absolute, and a bare name aborted this whole
        // command in a debug build: measured on 2026-08-25 with a real podman.
        var host = chock_container.Runtime.Host{
            .program = ready.program,
            .env = env,
        };
        const present = chock_container.Image.present(arena, io, .{
            .reference = reference,
            // Not read by `present`, and a path all the same: a field with a
            // value that would be wrong if it were read is worse than one that
            // is right and ignored.
            .cache_dir = project_root,
            .kind = ready.kind,
            .trust = ready.trust,
            .runner = host.runner(),
        }) catch false;

        if (!present) return .{ .image_unusable = std.fmt.allocPrint(
            arena,
            "this project names the image {s} and it is not on this machine. Run `{s} pull {s}` first",
            .{ reference, ready.kind.program(), reference },
        ) catch "this project names an image that is not on this machine" };

        return .{ .image = reference };
    }

    if (dev_shell == .read) return .dev_shell;

    var count: usize = 0;
    for (run.host_toolchain_candidates) |path| {
        const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch continue;
        if (stat.kind != .directory) continue;
        // A machine with a Nix store mounts that and nothing else, which is
        // the one rule `hostToolchainPaths` states in full.
        if (std.mem.eql(u8, path, run.host_toolchain_candidates[0])) return .{ .host = 1 };
        count += 1;
    }
    if (count == 0) return .none;
    return .{ .host = count };
}

fn measureCredential(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) CredentialState {
    const config_dir = chock_auth.paths.configDir(arena, env) catch |err| return .{
        .unconfigured = @errorName(err),
    };
    const data_dir = chock_auth.paths.dataDir(arena, env) catch |err| return .{
        .unconfigured = @errorName(err),
    };

    var config_diag: ?chock_auth.config.Diagnostic = null;
    defer if (config_diag) |*d| d.deinit(arena);
    var config = chock_auth.config.load(arena, io, config_dir, &config_diag) catch |err| {
        if (err == error.NoConfigFile) return .{
            .unconfigured = std.fmt.allocPrint(arena, "there is no configuration at {s}/{s}", .{
                config_dir,
                chock_auth.config.file_name,
            }) catch "there is no configuration",
        };
        if (config_diag) |*d| return .{
            .unconfigured = std.fmt.allocPrint(arena, "{f}", .{d}) catch @errorName(err),
        };
        return .{ .unconfigured = @errorName(err) };
    };

    const instance = config.defaultInstance() orelse return .{
        .unconfigured = std.fmt.allocPrint(
            arena,
            "the configuration names {d} providers and no default",
            .{config.instances.len},
        ) catch "the configuration names no default provider",
    };
    if (config.default_model == null) return .{
        .unconfigured = "the configuration names no default model",
    };

    const driver = chock_auth.store.Driver{ .data_dir = data_dir };
    const store = chock_auth.store.Store{ .data_dir = data_dir, .secrets = driver.secrets() };
    var lookup_diag: ?chock_auth.lookup.Diagnostic = null;
    defer if (lookup_diag) |*d| d.deinit(arena);
    const resolved = chock_auth.lookup.resolve(
        arena,
        io,
        instance,
        config_dir,
        store,
        &lookup_diag,
    ) catch |err| {
        if (lookup_diag) |*d| return .{
            .unreadable = std.fmt.allocPrint(arena, "{f}", .{d}) catch @errorName(err),
        };
        return .{ .unreadable = @errorName(err) };
    };
    if (chock_auth.lookup.credentialIsMissing(instance, resolved.source)) return .{
        .missing = std.fmt.allocPrint(
            arena,
            "the provider {s} talks to {s} and no credential was found",
            .{ instance.name, instance.base_url },
        ) catch "the default provider needs a credential and none was found",
    };
    if (resolved.source == .none) return .not_needed;
    return .{ .found = resolved.source.describe() };
}

/// One step a probe child runs, and the byte it reports itself with.
///
/// **Sent over a pipe and read back as untrusted bytes.** A child that dies
/// halfway writes fewer records, and the parent then knows exactly how far it
/// got instead of guessing.
const Step = enum(u8) {
    namespaces = 1,
    tmpfs = 2,
    overlayfs = 3,
    seccomp = 4,
};

/// What one step answered.
const Answer = enum(u8) {
    ok = 0,
    /// This machine does not have the mechanism at all.
    absent = 1,
    /// It has it and the child was refused.
    refused = 2,
    /// **The namespaces step only.** The user namespace was made, and the id
    /// map inside it could not be written, so every process in it would be
    /// the overflow user and could own no file. See `runProbes`.
    refused_id_map = 3,
};

/// One record on the pipe: which step, and what it answered.
const record_bytes = 2;

/// What a probe child is asked to do. **Every field narrows**, so a plan that
/// asks for less can never measure more than the machine gave.
const Plan = struct {
    network: sandbox.namespace.Network,
    mount: bool,
    /// Mount a capped tmpfs and an overlay once the namespaces are up. Only
    /// ever true with `mount`, because a mount made without a mount namespace
    /// is a mount on the machine a person is using.
    filesystems: bool,
    /// Install the seccomp filter. Last, because it cannot be removed.
    seccomp: bool,
};

/// What one child reported, one slot per step, null for a step it never
/// reached.
const ChildReport = struct {
    namespaces: ?Answer = null,
    tmpfs: ?Answer = null,
    overlayfs: ?Answer = null,
    seccomp: ?Answer = null,
};

/// The size the tmpfs probe asks for. Small: this asks whether a capped area
/// can be mounted at all, not how large one may be.
const probe_tmpfs_bytes: u64 = 1 << 20;

/// What every probe directory under this project's own session directory
/// starts with. `probeDirName` puts this run's own process id after it.
/// Removed before this command returns, and named so that a directory
/// somebody finds after a crash says what made it.
const probe_dir_prefix = "doctor.probe";

/// The probe directory of **this** run, written into `buffer`.
///
/// **The process id is part of the name, and it is not decoration.** The
/// session directory is keyed by project, so two `chock doctor` runs on one
/// project used to build the same tree, mount an overlay in it, and then each
/// remove the other's. The report then said the kernel refused an overlay
/// mount when the kernel had refused nothing, which is a wrong measurement a
/// person cannot tell from a real one. Measured at 31 failures in 100 with
/// four runs at a time, and 68 in 160 with eight. `linux/cgroup.zig` names a
/// cgroup this way for the same reason.
fn probeDirName(buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, probe_dir_prefix ++ "-{d}", .{std.posix.system.getpid()});
}

/// Remove the probe tree of every run that is gone, under `project_dir`.
///
/// **This is what the process id in the name costs, and it is paid here.** A
/// constant name meant the next run reused the tree a crash left and removed
/// it at the end. A name of this run's own cannot do that, so a crash would
/// leave a directory nobody can explain, which is the very thing
/// `removeProbeRoot` exists to prevent.
///
/// **A tree is removed only when its own process is gone.** Signal 0 asks the
/// kernel whether a process id is in use and sends nothing. `EPERM` says the
/// id belongs to somebody else, which is still a live id, so the tree stays:
/// removing a tree a running `chock doctor` has an overlay mounted in is the
/// fault this whole change is about.
///
/// `remove` is the caller's own remover, because the two platforms unmake
/// different trees. See `removeProbeRoot` for the chmod a Linux overlay needs
/// and `std.os.linux` has, which is a call that does not compile for Darwin.
fn removeDeadProbeRoots(
    arena: std.mem.Allocator,
    io: std.Io,
    project_dir: []const u8,
    comptime remove: fn (std.mem.Allocator, std.Io, []const u8) void,
) void {
    var dir = std.Io.Dir.openDirAbsolute(io, project_dir, .{ .iterate = true }) catch return;
    defer dir.close(io);

    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (!std.mem.startsWith(u8, entry.name, probe_dir_prefix ++ "-")) continue;
        const digits = entry.name[probe_dir_prefix.len + 1 ..];
        const pid = std.fmt.parseInt(std.posix.pid_t, digits, 10) catch continue;
        // Signal 0 is not a member of `std.posix.SIG` and the enum is open, so
        // it is written this way. `lib/chock-sandbox/linux/cgroup.zig` asks
        // the same question of a cgroup name and says the same thing about the
        // safe direction: a leak, never a live tree removed.
        std.posix.kill(pid, @enumFromInt(0)) catch |err| switch (err) {
            error.ProcessNotFound => {
                const path = std.fs.path.join(arena, &.{ project_dir, entry.name }) catch continue;
                remove(arena, io, path);
            },
            else => {},
        };
    }
}

/// Unmake a Seatbelt probe tree, which is one directory holding two files and
/// needs nothing `deleteTree` cannot do on its own.
fn removeSeatbeltProbeRoot(arena: std.mem.Allocator, io: std.Io, root: []const u8) void {
    _ = arena;
    std.Io.Dir.cwd().deleteTree(io, root) catch {};
}

/// Measure every sandbox layer.
///
/// **Every row here answers "may this process do it", which is the question a
/// `spawn` asks from this same process.** So a machine that refuses one of
/// them refuses a tool call, whatever a machine outside a container would say,
/// and no other row needs a vantage. The cgroup row is the one exception, and
/// not by choice: its answer is derived from a path that a cgroup namespace
/// rewrites, so the refusal it reports can be a refusal of a cgroup this
/// process is not in. See `cgroup.Vantage`.
fn measureLayers(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    m: *Measured,
) void {
    // Landlock is the one mechanism with a probe that changes nothing, so it
    // is read here and not in a child.
    if (sandbox.landlock.probeAbi()) |abi| {
        m.landlock = .ok;
        m.landlock_abi = abi;
    } else |err| {
        m.landlock = switch (err) {
            error.NotSupported => .{ .absent = "the kernel answered that it has no Landlock" },
            error.Unexpected => .{ .refused = "the kernel refused the Landlock version call" },
        };
    }

    m.pidfd = probePidfd();
    // The vantage first, because it is the question the answer below is only
    // true of. Order changes nothing: reading it makes no cgroup and moves
    // nothing.
    m.cgroup_vantage = sandbox.cgroup.readVantage();
    m.cgroup = probeCgroup();

    // Somewhere to mount things. Removed again below, whatever happens.
    const probe_root = probeRoot(arena, io, env, project_root);
    defer if (probe_root) |root| removeProbeRoot(arena, io, root);

    const filter = sandbox.seccomp.build(arena, .{}) catch null;

    // The whole sandbox at once. A machine that gives it gives every layer,
    // and one fork is the whole measurement.
    const whole = runChild(.{
        .network = .none,
        .mount = true,
        .filesystems = probe_root != null,
        .seccomp = filter != null,
    }, probe_root, filter);

    applySeccomp(m, whole, filter);
    applyFilesystems(m, whole, probe_root);

    if (whole.namespaces == .ok) {
        m.user_namespace = .ok;
        m.mount_namespace = .ok;
        m.pid_namespace = .ok;
        m.ipc_namespace = .ok;
        m.network_namespace = .ok;
        return;
    }

    narrowNamespaces(arena, m, whole, filter);
}

/// The probe file a Seatbelt run may read, and the one it may not.
const seatbelt_inside_name = "inside.txt";
const seatbelt_outside_name = "outside.txt";

/// Measure the Darwin layers.
///
/// **Through `Sandbox.spawn` itself, and never through a profile this command
/// built for the occasion.** The whole failure this file exists to avoid is a
/// report of a boundary nobody tried to cross, and a Seatbelt profile is
/// exactly the shape of thing that fools a stand-in: it compiles, it applies,
/// and it can deny nothing at all. So the measurement is two real sandboxes
/// running two real programs: one reads a file the config permits and must
/// succeed, and one reads a file beside it that the config does not permit and
/// must be refused. **Both halves, because a sandbox that denied everything
/// would pass a check that only ever looked for a refusal.**
///
/// The resource limits are measured by the same two calls. The Darwin driver
/// refuses the spawn when a limit the caller asked for could not be set, so a
/// run that reached the program at all proves the three Darwin honours went on.
/// The other four have no mechanism, and their rows say so without asking.
fn measureSeatbelt(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    m: *Measured,
) void {
    // **Not `probeRoot` and not `removeProbeRoot`.** Those two make and unmake
    // the four directories an overlay mount needs, and the removal chmods a
    // work directory the kernel left behind with mode 0, through a Linux only
    // call. Nothing here mounts anything, so the tree is one directory.
    const root = seatbeltProbeRoot(arena, io, env, project_root) orelse {
        m.seatbelt = .{ .refused = "no directory could be made to measure it in" };
        m.rlimits = .{ .refused = "no directory could be made to measure it in" };
        return;
    };
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};

    const inside_dir = std.fs.path.join(arena, &.{ root, "inside" }) catch return;
    makeDirAll(io, inside_dir) catch {
        m.seatbelt = .{ .refused = "no directory could be made to measure it in" };
        m.rlimits = .{ .refused = "no directory could be made to measure it in" };
        return;
    };
    const inside = std.fs.path.join(arena, &.{ inside_dir, seatbelt_inside_name }) catch return;
    const outside = std.fs.path.join(arena, &.{ root, seatbelt_outside_name }) catch return;
    for ([_][]const u8{ inside, outside }) |path| {
        var file = std.Io.Dir.createFileAbsolute(io, path, .{}) catch {
            m.seatbelt = .{ .refused = "the probe files could not be written" };
            m.rlimits = .{ .refused = "the probe files could not be written" };
            return;
        };
        defer file.close(io);
        file.writeStreamingAll(io, "probe\n") catch {};
    }

    // One directory permitted, at its own path, which is the only shape this
    // platform can express: see `darwin/driver.zig`'s own `expressibleOn`.
    const mounts = [_]sandbox.namespace.Mount{.{ .bind = .{
        .source = inside_dir,
        .target = inside_dir,
        .read_only = true,
    } }};
    const rules = [_]sandbox.Config.Rule{.{
        .path = inside_dir,
        .access = sandbox.landlock.AccessFs.read_only,
    }};

    const quiet = std.Io.Dir.openFileAbsolute(io, "/dev/null", .{ .mode = .read_write }) catch {
        m.seatbelt = .{ .refused = "/dev/null could not be opened" };
        m.rlimits = .{ .refused = "/dev/null could not be opened" };
        return;
    };
    defer quiet.close(io);

    // **Null is never a refusal**, on either call. A program the system killed
    // says nothing about the boundary, and reading it as a refusal would report
    // a layer that was never measured.
    const permitted = seatbeltProbeRan(arena, &mounts, &rules, inside_dir, inside, quiet.handle) orelse {
        // The sandbox never came up, so nothing was measured and nothing may be
        // claimed. The limits ride on the same call for the same reason: the
        // Darwin driver refuses a spawn when a limit it was asked for could not
        // be set, so a run that reached the program proves the three went on.
        m.seatbelt = .{ .refused = "a sandboxed program could not be started at all" };
        m.rlimits = .{ .refused = "a sandboxed program could not be started at all" };
        return;
    };
    m.rlimits = .ok;

    const reached_outside = seatbeltProbeRan(arena, &mounts, &rules, inside_dir, outside, quiet.handle) orelse {
        m.seatbelt = .{ .refused = "the program that should have been refused answered nothing at all" };
        return;
    };

    if (!permitted) {
        m.seatbelt = .{ .refused = "a path the profile permits could not be read, so the profile is wrong" };
    } else if (reached_outside) {
        m.seatbelt = .{ .refused = "a path the profile does not permit was read anyway" };
    } else {
        m.seatbelt = .ok;
    }

    // A tool call needs more than the workspace, and each of the rest still
    // asks for a path to appear somewhere else. Asked of the driver's own
    // function rather than assumed: see `toolCallRow`.
    m.tool_call_refused = seatbeltToolCallRefusal(arena, root);
}

/// One directory under this project's own session directory, for the Seatbelt
/// measurement to run in. Removed before this command returns.
///
/// **The session directory and never a temporary one.** Seatbelt matches the
/// path the kernel resolved, and on macOS `/tmp` is a symbolic link to
/// `/private/tmp`: a rule naming a path through that link matches nothing at
/// all, so the whole measurement would read as a sandbox that denies
/// everything. Measured on 2026-08-25.
fn seatbeltProbeRoot(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) ?[]const u8 {
    const project_dir = session_paths.projectDir(arena, env, project_root) catch return null;
    var name_buffer: [64]u8 = undefined;
    const name = probeDirName(&name_buffer) catch return null;
    const root = std.fs.path.join(arena, &.{ project_dir, name }) catch return null;
    makeDirAll(io, root) catch return null;
    removeDeadProbeRoots(arena, io, project_dir, removeSeatbeltProbeRoot);
    return root;
}

/// Run one program inside a real sandbox and say whether it read `target`.
/// Null when the sandbox never came up at all, which is a different fact from
/// a program that was refused.
fn seatbeltProbeRan(
    arena: std.mem.Allocator,
    mounts: []const sandbox.namespace.Mount,
    rules: []const sandbox.Config.Rule,
    cwd: []const u8,
    target: []const u8,
    quiet_fd: std.posix.fd_t,
) ?bool {
    const argv = [_][]const u8{ "/bin/cat", target };
    const term = sandbox.spawn(arena, .{
        .root = "/",
        .mounts = mounts,
        .rules = rules,
        .cwd = cwd,
        .env = &.{},
        .stdout_fd = quiet_fd,
        .stderr_fd = quiet_fd,
    }, &argv, null, null) catch return null;
    return switch (term) {
        .exited => |code| code == 0,
        // Killed by a signal says nothing about the boundary, and must never be
        // read as a refusal the sandbox made.
        else => null,
    };
}

/// Why a whole tool call is still refused, or null when one runs.
///
/// **The driver's own answer, about the paths a session really mounts.** Each
/// target is asked of the library that owns it, through the same
/// `sandboxDirFor` call `lib/chock-core/tools.zig` makes when it assembles a
/// real tool call. So this row measures the config a session would hand the
/// driver and not a constant beside it: a build that moves a path is told the
/// runtime prefix and a build that moves none is told the host path itself,
/// and the row follows the library rather than going stale behind it.
fn seatbeltToolCallRefusal(arena: std.mem.Allocator, root: []const u8) ?[]const u8 {
    const also_mounted = [_][]const u8{
        chock_core.scratchpad.sandboxDirFor(root),
        chock_core.cache.sandboxDirFor(root),
        chock_core.tasks.sandboxDirFor(root),
    };
    for (also_mounted) |target| {
        const config = sandbox.Config{
            .root = "/",
            .mounts = &.{.{ .bind = .{ .source = root, .target = target, .read_only = false } }},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
        };
        const why = sandbox.darwin_driver_for_testing.expressibleOn(config) orelse continue;
        return std.fmt.allocPrint(arena, "a tool call needs {s}, for {s}", .{ why.text(), target }) catch
            "a tool call needs a path to appear somewhere else, and macos has no bind mount";
    }
    return null;
}

/// Tell apart which namespace was refused, with the only two narrower plans
/// `namespace.enter` offers.
///
/// **The user, pid and ipc namespaces are one answer and always will be.**
/// `enter` takes all three unconditionally and has no field for any of them,
/// on purpose: without the pid namespace every process the user owns is a
/// legal signal target, and without the ipc namespace shared memory crosses
/// the boundary. So a machine that refuses one refuses the sandbox, and this
/// reports them together rather than inventing a distinction the library does
/// not make.
fn narrowNamespaces(
    arena: std.mem.Allocator,
    m: *Measured,
    whole: ChildReport,
    filter: ?[]sandbox.bpf.Insn,
) void {
    const failed = whole.namespaces orelse Answer.refused;
    const bare = runChild(.{
        .network = .host,
        .mount = false,
        .filesystems = false,
        // Already measured by the whole plan when it got that far.
        .seccomp = whole.seccomp == null and filter != null,
    }, null, filter);
    applySeccomp(m, bare, filter);

    if (bare.namespaces != Answer.ok) {
        const why = whyFor(failed, namespaceRefusalText(arena, failed));
        m.user_namespace = why;
        m.pid_namespace = why;
        m.ipc_namespace = why;
        // Both are built on the user namespace, so neither could be reached.
        // Said as a refusal of this process and not as a machine that lacks
        // them, because that is what was measured.
        m.mount_namespace = .{ .refused = "the user namespace it is built on was refused" };
        m.network_namespace = .{ .refused = "the user namespace it is built on was refused" };
        return;
    }

    m.user_namespace = .ok;
    m.pid_namespace = .ok;
    m.ipc_namespace = .ok;

    const with_mount = runChild(.{
        .network = .host,
        .mount = true,
        .filesystems = false,
        .seccomp = false,
    }, null, null);
    if (with_mount.namespaces == Answer.ok) {
        m.mount_namespace = .ok;
        m.network_namespace = whyFor(failed, "the kernel refused a network namespace to this process");
        return;
    }
    m.mount_namespace = whyFor(with_mount.namespaces orelse Answer.refused, "the kernel refused a mount namespace to this process");
    m.network_namespace = .{ .refused = "the mount namespace beside it was refused, so this was never reached" };
}

fn applySeccomp(m: *Measured, report: ChildReport, filter: ?[]sandbox.bpf.Insn) void {
    if (filter == null) {
        m.seccomp = .{ .refused = "the filter could not be built, which is chock's own fault and not this machine's" };
        return;
    }
    const answer = report.seccomp orelse return;
    m.seccomp = whyFor(answer, "the kernel refused a seccomp filter to this process");
}

fn applyFilesystems(m: *Measured, report: ChildReport, probe_root: ?[]const u8) void {
    if (probe_root == null) {
        const why = Probe{ .refused = "chock's own session directory could not be made, so nothing could be mounted to find out" };
        m.tmpfs = why;
        m.overlayfs = why;
        return;
    }
    if (report.tmpfs) |answer| {
        m.tmpfs = whyFor(answer, "the kernel refused a tmpfs to this process");
    } else {
        m.tmpfs = .{ .refused = "the mount namespace it needs was refused" };
    }
    if (report.overlayfs) |answer| {
        m.overlayfs = whyFor(answer, "the kernel refused an overlay mount to this process");
    } else {
        m.overlayfs = .{ .refused = "the mount namespace it needs was refused" };
    }
}

/// One answer, as a probe. `refused_text` is what a refusal says; an absence
/// always says the same thing, because a kernel that answers "no such
/// mechanism" is a fact about the machine and not about this process.
fn whyFor(answer: Answer, refused_text: []const u8) Probe {
    return switch (answer) {
        .ok => .ok,
        .absent => .{ .absent = "the kernel answered that it does not have it" },
        // The two refusals read the same text on purpose. Which one it was is
        // already in the words the caller built: see `namespaceRefusalText`,
        // the one caller that can ever be handed `refused_id_map`.
        .refused, .refused_id_map => .{ .refused = refused_text },
    };
}

/// Why the namespaces were refused, in the words a person acts on.
///
/// **Two facts, and the second one is the file to change.** `answer` is what
/// the probe child measured, and it can say that the user namespace was made
/// and the id map inside it was not, which is what Ubuntu's
/// `kernel.apparmor_restrict_unprivileged_userns` does; a report that called
/// that a refused user namespace would send a person to `max_user_namespaces`,
/// which is not the file to change. The call and the errno come from
/// `probeAvailability`, which the child could not carry back: it answers over
/// a two byte pipe, and this runs in the parent, where there is an allocator
/// and a terminal.
///
/// **One more fork, and it is worth it.** `chock doctor` is the command a
/// person runs when the sandbox will not come up, and the errno is the whole
/// diagnosis. A probe that answers anything but a refusal is left out rather
/// than argued with: the measurement above is the one that really ran, and a
/// second opinion that disagrees says nothing about which is right.
fn namespaceRefusalText(arena: std.mem.Allocator, answer: Answer) []const u8 {
    const measured = switch (answer) {
        .refused_id_map => "the kernel made the user namespace and refused the id map write inside it",
        .ok, .absent, .refused => "the kernel refused a user namespace to this process",
    };
    const detail = sandbox.namespace.probeAvailability();
    if (detail != .unavailable) return measured;
    return std.fmt.allocPrint(arena, "{s}, and {f}", .{ measured, detail.unavailable }) catch measured;
}

/// Ask the kernel for a handle on this process, and give it straight back.
///
/// The Linux driver opens one of these for every sandboxed process and
/// refuses rather than run a call it could not cancel, so a machine that says
/// no here is a machine `spawn` refuses on. Its own comment records that any
/// kernel with Landlock already has this call; measuring it anyway is what
/// makes the row a measurement.
fn probePidfd() Probe {
    const rc = linux.pidfd_open(linux.getpid(), 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => {
            _ = linux.close(@intCast(rc));
            return .ok;
        },
        .NOSYS => .{ .absent = "this kernel has no pidfd_open" },
        else => .{ .refused = "the kernel refused a handle on this process" },
    };
}

/// Make a cgroup exactly the way a `spawn` would, read what it answered, and
/// remove it again.
///
/// **This is the only way to learn cgroup support**, because everything that
/// walks the delegated parents is private to `chock-sandbox`. It creates one
/// directory and removes it, and it never moves this process into it: `join`
/// is a separate call and nothing here makes it.
fn probeCgroup() CgroupSupport {
    const limits = sandbox.Sandbox.Limits{};
    // `create` asserts that at least one bound is asked for, so the defaults
    // are read from the same type a session uses rather than invented here.
    var made = sandbox.cgroup.Cgroup.create(
        limits.memory_bytes orelse probe_tmpfs_bytes,
        limits.processes orelse 1,
        0,
    );
    defer made.destroy();
    return made.support;
}

/// Chock's own directory for this project, plus one directory to mount
/// things under. Null when it could not be made, which the caller reports as
/// a reason rather than as a kernel refusal.
fn probeRoot(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) ?[]const u8 {
    const project_dir = session_paths.projectDir(arena, env, project_root) catch return null;
    var name_buffer: [64]u8 = undefined;
    const name = probeDirName(&name_buffer) catch return null;
    const root = std.fs.path.join(arena, &.{ project_dir, name }) catch return null;
    for ([_][]const u8{ "lower", "upper", "work", "merged" }) |leaf| {
        const path = std.fs.path.join(arena, &.{ root, leaf }) catch return null;
        makeDirAll(io, path) catch return null;
    }
    removeDeadProbeRoots(arena, io, project_dir, removeProbeRoot);
    return root;
}

/// Remove the probe tree. **Nothing this command makes may outlive it**: a
/// directory somebody finds a month later under their own session directory
/// is a directory nobody can explain.
///
/// **The chmod is not optional.** An overlay mount makes `workdir/work` for
/// itself, with mode 0, and it stays on disk after the child's mount
/// namespace goes away. `deleteTree` cannot walk into a directory it may not
/// open, so without this the tree is half removed and `work/work` is left
/// behind. Measured on 2026-08-24.
fn removeProbeRoot(arena: std.mem.Allocator, io: std.Io, root: []const u8) void {
    if (std.fmt.allocPrintSentinel(arena, "{s}/work/work", .{root}, 0)) |path| {
        _ = linux.fchmodat(linux.AT.FDCWD, path.ptr, 0o755);
    } else |_| {}
    std.Io.Dir.cwd().deleteTree(io, root) catch {};
}

/// `mkdir -p`, for the one tree this command builds and removes again.
///
/// `src/session.zig`'s own is private and makes the directories a session
/// reads. This makes a directory nothing reads, and removes it before the
/// command returns.
fn makeDirAll(io: std.Io, path: []const u8) !void {
    if (path.len == 0) return;
    std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            try makeDirAll(io, parent);
            std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |second| switch (second) {
                error.PathAlreadyExists => return,
                else => return second,
            };
        },
        else => return err,
    };
}

/// Run one plan in a forked child and read what it reported.
///
/// **A child, and not this process.** A user namespace cannot be left once it
/// is entered, a seccomp filter cannot be removed, and the kernel refuses
/// `CLONE_NEWUSER` from a process with more than one thread. A fork carries
/// only the calling thread, so the child is single threaded whatever this
/// process is.
fn runChild(plan: Plan, probe_root: ?[]const u8, filter: ?[]sandbox.bpf.Insn) ChildReport {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return .{};

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return .{};
    }

    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        runProbes(plan, fds[1], probe_root, filter);
        // Never a return: this is a forked child of a program with an arena,
        // open files and a terminal, and none of that is this process's to
        // unwind.
        std.process.exit(0);
    }

    _ = linux.close(fds[1]);
    const report = readReport(fds[0]);
    _ = linux.close(fds[0]);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);

    // A child that died before it wrote anything measured nothing, and a slot
    // left null is exactly that. Nothing here turns silence into an answer.
    return report;
}

fn readReport(read_fd: i32) ChildReport {
    var report = ChildReport{};
    var buffer: [record_bytes * 8]u8 = undefined;
    var held: usize = 0;

    while (held + record_bytes <= buffer.len) {
        const rc = linux.read(read_fd, buffer[held..].ptr, buffer.len - held);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => break,
        }
        if (rc == 0) break;
        held += rc;
    }

    var index: usize = 0;
    while (index + record_bytes <= held) : (index += record_bytes) {
        // The bytes came over a pipe, so they are read with `fromInt` and
        // never with `@enumFromInt`: a byte that names no step is dropped
        // rather than turned into an invalid tag.
        const step = std.enums.fromInt(Step, buffer[index]) orelse continue;
        const answer = std.enums.fromInt(Answer, buffer[index + 1]) orelse continue;
        switch (step) {
            .namespaces => report.namespaces = answer,
            .tmpfs => report.tmpfs = answer,
            .overlayfs => report.overlayfs = answer,
            .seccomp => report.seccomp = answer,
        }
    }
    return report;
}

/// The child. **Allocates nothing from the caller's allocator**, because a
/// fork may have happened while another thread held its lock. The one call
/// that needs an allocator gets a fixed buffer of its own.
fn runProbes(plan: Plan, write_fd: i32, probe_root: ?[]const u8, filter: ?[]sandbox.bpf.Insn) void {
    // **No diagnostic, and that is not an oversight.** This child answers over
    // a two byte pipe and cannot print: see this function's own comment. So it
    // carries the state and never the errno, and the two states below are the
    // most it can say. `Sandbox.spawn` is where the errno reaches a caller, in
    // `SetupFailureRecord`.
    const entered = sandbox.namespace.enter(.{ .network = plan.network, .mount = plan.mount }, null);
    if (entered) |_| {
        say(write_fd, .namespaces, .ok);
    } else |err| {
        say(write_fd, .namespaces, switch (err) {
            // **The namespace was made and it is unusable, which is not the
            // same fact as a refusal.** Measured on 2026-08-25: Ubuntu 24.04
            // sets `kernel.apparmor_restrict_unprivileged_userns=1`, and a
            // process inside a nested user namespace there is given the
            // namespace and refused the id map. A report that called that a
            // refused user namespace would send a person to
            // `max_user_namespaces`, which is not the file to change.
            error.MapFailed => .refused_id_map,
            // Every one of these is this process being refused, and none of
            // them says the kernel has no namespaces. A kernel built without
            // them cannot run the machine this is measuring.
            error.NotPermitted, error.MultiThreaded, error.Unexpected => .refused,
        });
        // Nothing below can be measured without them, and a mount made with
        // no mount namespace is a mount on the machine a person is using.
        if (plan.seccomp) sayFilter(write_fd, filter);
        return;
    }

    if (plan.filesystems and plan.mount) {
        if (probe_root) |root| {
            probeMounts(write_fd, root);
        }
    }

    if (plan.seccomp) sayFilter(write_fd, filter);
}

fn probeMounts(write_fd: i32, root: []const u8) void {
    const scratch = sandbox.namespace.mountScratch(root, "cap", probe_tmpfs_bytes, null);
    if (scratch) |fd| {
        _ = linux.close(fd);
        say(write_fd, .tmpfs, .ok);
    } else |err| {
        say(write_fd, .tmpfs, mountAnswer(err));
    }

    // One buffer for the four paths and the option string `mountOverlay`
    // builds. Large enough for four paths and the options that name three of
    // them, and a shortfall answers `OutOfMemory`, which reads as this
    // program's own fault rather than the machine's.
    var scratch_bytes: [6 * std.fs.max_path_bytes]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch_bytes);

    var lower_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var upper_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var merged_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const lower = joinLeaf(&lower_buffer, root, "lower") orelse return;
    const upper = joinLeaf(&upper_buffer, root, "upper") orelse return;
    const work = joinLeaf(&work_buffer, root, "work") orelse return;
    const merged = joinLeaf(&merged_buffer, root, "merged") orelse return;

    if (sandbox.namespace.mountOverlay(fba.allocator(), .{
        .lower = lower,
        .upper = upper,
        .work = work,
        .target = merged,
    }, null)) {
        say(write_fd, .overlayfs, .ok);
    } else |err| {
        say(write_fd, .overlayfs, mountAnswer(err));
    }
}

fn mountAnswer(err: sandbox.namespace.MountError) Answer {
    return switch (err) {
        // The two the kernel answers when the filesystem is not there at all.
        error.OverlayNotSupported, error.KernelTooOld => .absent,
        error.NotPermitted,
        error.SourceMissing,
        error.OutOfMemory,
        // This probe passes no `Mount.deny` at all, so a denied path that is
        // a directory can never be what it hits. Named here rather than left
        // to an `else`, so a later mount fault still has to be read and
        // classified by whoever adds one.
        error.DenyTargetIsDirectory,
        error.Unexpected,
        => .refused,
    };
}

/// `a/b` in `buffer`, with no allocation. Null when it does not fit.
fn joinLeaf(buffer: []u8, a: []const u8, b: []const u8) ?[]const u8 {
    if (a.len + 1 + b.len > buffer.len) return null;
    @memcpy(buffer[0..a.len], a);
    buffer[a.len] = '/';
    @memcpy(buffer[a.len + 1 ..][0..b.len], b);
    return buffer[0 .. a.len + 1 + b.len];
}

/// Install the filter, and say what happened. **Last of the steps**, because
/// the filter cannot be removed and it refuses `unshare`.
fn sayFilter(write_fd: i32, filter: ?[]sandbox.bpf.Insn) void {
    const insns = filter orelse return;
    if (sandbox.seccomp.install(sandbox.bpf.Prog.init(insns))) {
        say(write_fd, .seccomp, .ok);
    } else |err| {
        say(write_fd, .seccomp, switch (err) {
            error.NotSupported => .absent,
            error.Rejected, error.Unexpected => .refused,
        });
    }
}

/// Write one record. A failed write is dropped: the parent reads a slot that
/// stayed null, which is "this step was never reported" and is the truth.
fn say(write_fd: i32, step: Step, answer: Answer) void {
    const record = [record_bytes]u8{ @intFromEnum(step), @intFromEnum(answer) };
    _ = linux.write(write_fd, &record, record.len);
}

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);
    defer env.deinit();

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const project_root = try resolveProject(arena, io, options.project);

    const measured = measure(arena, gpa, io, &env, project_root);
    const rows = try rowsFor(arena, measured);
    const verdict = verdictFor(rows);
    printReport(project_root, measured, rows, verdict);
    return exitFor(verdict).code();
}

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--project")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.project = args[index];
            continue;
        }
        return error.BadArguments;
    }
    return options;
}

/// The project this command is about, as an absolute path.
///
/// **The same two calls every other command's own `resolveProject` makes.**
/// Chock's own directories are keyed by the project's real path, so a
/// spelling this command resolved differently would read a different
/// directory from the one a session writes.
fn resolveProject(arena: std.mem.Allocator, io: std.Io, given: ?[]const u8) ![]const u8 {
    if (given) |path| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return arena.dupe(u8, path);
        defer dir.close(io);
        const len = dir.realPath(io, &buffer) catch return arena.dupe(u8, path);
        return arena.dupe(u8, buffer[0..len]);
    }
    return std.process.currentPathAlloc(io, arena);
}

const testing = std.testing;

/// A machine on which everything works, as a starting point a test mutates
/// one field of. **Not a default**: `Measured`'s own defaults are the honest
/// answer for a build that measured nothing, and a test that started from
/// those would be asserting on absence everywhere.
fn healthy() Measured {
    return .{
        .driver = sandbox.Sandbox.Guarantees.initFull(),
        // **Stated, and never read from this build's own driver.** These are
        // the Linux rows, and a test that let the host choose the family would
        // ask for a `landlock` row on a Mac and find none.
        .family = .namespaces,
        .user_namespace = .ok,
        .mount_namespace = .ok,
        .pid_namespace = .ok,
        .ipc_namespace = .ok,
        .network_namespace = .ok,
        .landlock = .ok,
        .landlock_abi = 6,
        .seccomp = .ok,
        .cgroup = .ok,
        .cgroup_vantage = .own,
        .overlayfs = .ok,
        .pidfd = .ok,
        .tmpfs = .ok,
        .git_program = "/run/current-system/sw/bin/git",
        .nix_program = "/run/current-system/sw/bin/nix",
        .dev_shell = .{ .read = false },
        // A machine with no container runtime, which is the ordinary healthy
        // machine: only a project that names an image needs one, so this row
        // stops nothing.
        .container = .not_installed,
        .toolchain = .dev_shell,
        .credential = .{ .found = "chock login" },
        .cache = .ok,
        .free_bytes = 8 * 1024 * 1024 * 1024,
        // A machine with a reader plugged in. **Not the machine these tests run
        // on**, which is the point: every row here is stated, so a report that
        // read the host instead of the measurement fails.
        .card_seal = .ok,
        .card_readers = 1,
    };
}

fn rowNamed(rows: []const Row, name: []const u8) ?Row {
    for (rows) |row| {
        if (std.mem.eql(u8, row.name, name)) return row;
    }
    return null;
}

test "a layer this machine has is still reported absent when the measurement says absent" {
    // **The fact this whole command exists for.** These tests run on a Linux
    // box with Landlock, a tmpfs and overlayfs. The report must come from what
    // was measured and never from what the platform usually has, so a
    // measurement that says "absent" gives an absent row here, on a machine
    // where the layer is present.
    //
    // Mutation check: make `rowsFor` read `builtin.os.tag` or
    // `sandbox.Sandbox.guarantees` for any of these three rows and every
    // expectation below flips.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.landlock = .{ .absent = "the kernel answered that it has no Landlock" };
    m.landlock_abi = null;
    m.overlayfs = .{ .absent = "the kernel answered that it does not have it" };
    m.tmpfs = .{ .absent = "the kernel answered that it does not have it" };

    const rows = try rowsFor(arena, m);

    try testing.expectEqual(ui.Layer.State.unsupported, rowNamed(rows, "landlock").?.state);
    try testing.expectEqual(ui.Layer.State.unsupported, rowNamed(rows, "overlayfs").?.state);
    try testing.expectEqual(ui.Layer.State.unsupported, rowNamed(rows, "disk cap tmpfs").?.state);

    // And the layers that were not touched are still on, so this is a report
    // over the measurement and not a report that gave up.
    try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, "user namespace").?.state);
    try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, "seccomp").?.state);
}

test "a layer the machine has and this process may not use is BLOCKED, not NONE" {
    // The state `src/ui.zig` declared and nothing produced. `unsupported`
    // says there is nothing to configure; `unavailable` says an administrator
    // can change something. A report that spelled the two the same way would
    // have a person looking for a kernel fault that is not there.
    //
    // Mutation check: map `Probe.refused` to `.unsupported` and the word on
    // this row becomes NONE, which tells a person to give up.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.user_namespace = .{ .refused = "the kernel refused a user namespace to this process" };
    const rows = try rowsFor(arena, m);

    const row = rowNamed(rows, "user namespace").?;
    try testing.expectEqual(ui.Layer.State.unavailable, row.state);
    // And the word is `BLOCKED` because this row stops a first run, which is
    // the other half of the same sentence: see `wordFor`.
    try testing.expect(row.blocks);
    try testing.expectEqualStrings("BLOCKED", wordFor(row));
    try testing.expect(row.state != .unsupported);
    // And it says what to do, which is the difference between a report and a
    // complaint.
    try testing.expect(std.mem.indexOf(u8, row.fix, "unprivileged_userns_clone") != null);
}

test "a project that gave up the write and execute rule does not read like one that kept it" {
    // **The whole reason this row exists.** A session that gave up a piece of
    // hardening has to be visible before it starts, not only in the log
    // afterwards. Two reports off the same machine, differing in nothing but
    // the project's own policy, must not print the same line.
    //
    // Mutation check: answer `.on` for `.relaxed` and the two rows below are
    // identical, which is the failure this test is written against.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const strict_rows = try rowsFor(arena, healthy());
    const strict = rowNamed(strict_rows, "write^execute").?;
    try testing.expectEqual(ui.Layer.State.on, strict.state);
    try testing.expectEqualStrings("OK", wordFor(strict));

    var m = healthy();
    m.write_execute = .relaxed;
    const relaxed_rows = try rowsFor(arena, m);
    const relaxed = rowNamed(relaxed_rows, "write^execute").?;
    try testing.expectEqual(ui.Layer.State.off, relaxed.state);
    try testing.expectEqualStrings("OFF", wordFor(relaxed));

    // **`off` and never `unsupported` or `unavailable`.** Those two say the
    // machine cannot give the layer, or would not let this process have it, and
    // this machine can and would. A report that spelled it either way would
    // send a person looking for a kernel fault that is not there.
    try testing.expect(relaxed.state != .unsupported);
    try testing.expect(relaxed.state != .unavailable);

    // And the line names the rule a person has to find to change it.
    try testing.expect(std.mem.indexOf(u8, relaxed.means, chock_policy.hardening.jit_action) != null);

    // It does not stop a first run, in either form. W^X is hardening and not a
    // boundary: see the row's own comment in `rowsFor`.
    try testing.expect(!strict.blocks);
    try testing.expect(!relaxed.blocks);
}

test "the report reads the same rules a session reads, and an org bundle can take the row back" {
    // **`chock doctor` and `chock run` must not answer differently.** The
    // report reads `chock.zon` under the installation's own bundle, the same
    // fold `src/run.zig` makes, so a report that said a session would give up
    // hardening an organisation has already forbidden would be a lie in the
    // dangerous direction.
    //
    // This states the fold itself rather than spawning a session, because
    // `measureHardening` reads a real data directory and a real project root.
    // The two halves it joins are each proven in `lib/chock-policy/hardening.zig`.
    const allocator = testing.allocator;
    const source =
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "sandbox.jit", .decision = .allow },
        \\} } }
    ;
    const key: chock_policy.table.Key = .{
        .agent_kind = doctor_agent_kind,
        .model = no_default_model,
        .tool = chock_broker.actions.self_asked_tool,
        .action = chock_policy.hardening.jit_action,
    };

    const alone = try chock_policy.table.Table.parse(allocator, source, null);
    defer chock_policy.table.Table.destroy(allocator, alone);
    try testing.expectEqual(
        chock_policy.hardening.WriteExecute.relaxed,
        chock_policy.hardening.writeExecuteFor(alone.evaluateChain(&.{doctor_agent_kind}, key, null)),
    );

    const org_rules = [_]chock_policy.table.Rule{
        .{ .action = chock_policy.hardening.jit_action, .decision = .deny },
    };
    const under_org = try chock_policy.table.Table.parseUnder(allocator, source, &org_rules, null);
    defer chock_policy.table.Table.destroy(allocator, under_org);
    try testing.expectEqual(
        chock_policy.hardening.WriteExecute.strict,
        chock_policy.hardening.writeExecuteFor(under_org.evaluateChain(&.{doctor_agent_kind}, key, null)),
    );
}

test "a cgroup refusal measured inside a namespace says so, and never blames a working init system" {
    // The false negative this row was reported for. A process in a cgroup
    // namespace reads `0::/` for a cgroup deep in the machine's tree, so
    // `cgroup.Cgroup.create` walks a tree it is not in and is refused there.
    // Measured on 2026-08-24 on a systemd box whose user slice delegates
    // `memory` and `pids`: `chock doctor` said BLOCKED from inside
    // `unshare --user --cgroup` and OK outside it.
    //
    // Mutation check: pass the vantage no further than `Measured`, or answer
    // `own` for every process, and the two rows below become one sentence.
    // Then a person is sent to an init system that already delegates.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.cgroup = .{ .unavailable = .no_delegated_parent };

    m.cgroup_vantage = .own;
    const on_the_machine = rowNamed(try rowsFor(arena, m), "cgroup v2").?;
    try testing.expect(std.mem.indexOf(u8, on_the_machine.means, "namespace") == null);
    try testing.expect(std.mem.indexOf(u8, on_the_machine.fix, "init system") != null);

    m.cgroup_vantage = .foreign;
    const in_a_container = rowNamed(try rowsFor(arena, m), "cgroup v2").?;
    // It says which question it answered, and it stops telling a person to
    // configure a machine this measurement never reached.
    try testing.expect(std.mem.indexOf(u8, in_a_container.means, "cgroup namespace") != null);
    try testing.expect(std.mem.indexOf(u8, in_a_container.means, "not for the machine outside it") != null);
    try testing.expect(std.mem.indexOf(u8, in_a_container.fix, "init system") == null);
    try testing.expect(std.mem.indexOf(u8, in_a_container.fix, "outside it") != null);
    try testing.expect(!std.mem.eql(u8, on_the_machine.means, in_a_container.means));

    // A tree the kernel has and this mount namespace hides reads the same way,
    // and it is not NONE: NONE says there is nothing to configure, which is
    // false of a machine that delegates. It is not BLOCKED either, because a
    // machine with no cgroup still runs a session on the rlimit floor.
    m.cgroup = .{ .unavailable = .no_cgroup2_mount };
    m.cgroup_vantage = .not_mounted;
    const hidden = rowNamed(try rowsFor(arena, m), "cgroup v2").?;
    try testing.expectEqual(ui.Layer.State.unavailable, hidden.state);
    try testing.expect(!hidden.blocks);
    try testing.expectEqualStrings("DEGRADED", wordFor(hidden));
    try testing.expect(std.mem.indexOf(u8, hidden.means, "not for the machine outside it") != null);

    // And a vantage that could not be read never claims to be this machine's.
    m.cgroup = .{ .unavailable = .no_delegated_parent };
    m.cgroup_vantage = .unknown;
    const unproven = rowNamed(try rowsFor(arena, m), "cgroup v2").?;
    try testing.expect(std.mem.indexOf(u8, unproven.means, "may be") != null);
    try testing.expect(!std.mem.eql(u8, unproven.means, on_the_machine.means));

    // A directory that could not be made under a parent that does delegate is
    // a fault in where chock was started, and the row says that instead of
    // sending a person to an init system that is already doing its part. See
    // `fixFor`.
    m.cgroup = .{ .unavailable = .create_refused };
    m.cgroup_vantage = .own;
    const refused = rowNamed(try rowsFor(arena, m), "cgroup v2").?;
    try testing.expect(std.mem.indexOf(u8, refused.fix, "init system") == null);
    try testing.expect(std.mem.indexOf(u8, refused.fix, "already delegated") != null);
    try testing.expect(!std.mem.eql(u8, refused.fix, on_the_machine.fix));
}

test "the report is readable with no colour: every row carries a glyph, a word, and a sentence when something is wrong" {
    // No fact may rest on colour alone, and this report is read in a pipe more
    // often than on a screen. So every row must be legible as plain text: a
    // glyph, a word, and, for a row that is not on, a sentence saying what this
    // machine answered.
    //
    // Mutation check: return an empty string from `wordFor` for `.on`, the way
    // the session header does, and the word assertion below fails.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.cgroup = .{ .unavailable = .no_delegated_parent };
    m.seccomp = .{ .refused = "the kernel refused a seccomp filter to this process" };
    m.dev_shell = .no_flake;
    const rows = try rowsFor(arena, m);

    try testing.expect(rows.len > 0);
    var not_on: usize = 0;
    for (rows) |row| {
        try testing.expect(row.name.len != 0);
        try testing.expect(row.state.glyph().len != 0);
        try testing.expect(wordFor(row).len != 0);
        if (row.state == .on) {
            // Either a measurement worth keeping or a lesson for `--verbose`.
            // A row with neither says nothing at all with `--verbose` on.
            try testing.expect(row.means.len != 0 or row.why.len != 0);
            continue;
        }
        not_on += 1;
        // The rows this command is for. Never quiet.
        try testing.expect(row.means.len != 0);
    }
    // The machine above really does have rows that are not on, so the
    // assertion in the loop is not vacuous.
    try testing.expect(not_on >= 2);

    // The states that are not on carry different words, so a reader can tell
    // "nothing to configure" from "you were refused", and a row that stops a
    // first run from a row that only costs the run something.
    const stated: Row = .{ .name = "stated", .state = .on, .means = "" };
    try testing.expectEqualStrings("OK", wordFor(stated));
    try testing.expectEqualStrings("OFF", wordFor(.{ .name = "x", .state = .off, .means = "y" }));
    try testing.expectEqualStrings("NONE", wordFor(.{ .name = "x", .state = .unsupported, .means = "y" }));
    try testing.expectEqualStrings("DEGRADED", wordFor(.{ .name = "x", .state = .unavailable, .means = "y" }));
    // Every state that is not on says `BLOCKED` when the row stops a first
    // run, so a kernel with no Landlock is not read as a machine with nothing
    // to configure while the footer counts it.
    for ([_]ui.Layer.State{ .off, .unsupported, .unavailable }) |state| {
        try testing.expectEqualStrings("BLOCKED", wordFor(.{
            .name = "x",
            .state = state,
            .means = "y",
            .blocks = true,
        }));
    }

    // And a row that is not on says what to do, or says in its sentence that
    // nothing can be done.
    const cgroup_row = rowNamed(rows, "cgroup v2").?;
    try testing.expect(cgroup_row.fix.len != 0);
    try testing.expect(std.mem.indexOf(u8, cgroup_row.means, "rlimit floor") != null);
}

test "the word BLOCKED stands beside exactly the rows the footer counts" {
    // The contradiction this word was changed for, read on a Mac on
    // 2026-08-25: `dev shell` and `credential` both said `BLOCKED` and the
    // footer said "Rows that stop a first run: 1 of 21". A person counts the
    // column and the report argues with itself, which costs the reader every
    // other row as well.
    //
    // Mutation check: make `wordFor` ignore `blocks` and answer from the state
    // alone, and this fails on the dev shell row.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    // Two rows in the same state, and only one of them stops a first run.
    // That pair is what the state alone cannot tell apart.
    m.dev_shell = .{ .failed = "nix could not evaluate it" };
    m.credential = .{ .unconfigured = "no provider is named in config.zon" };
    const rows = try rowsFor(arena, m);

    var said: usize = 0;
    for (rows) |row| {
        const says_blocked = std.mem.eql(u8, wordFor(row), "BLOCKED");
        try testing.expectEqual(row.state != .on and row.blocks, says_blocked);
        if (says_blocked) said += 1;
    }
    try testing.expectEqual(countBlocking(rows), said);
    try testing.expectEqual(@as(usize, 1), said);

    const dev = rowNamed(rows, "dev shell").?;
    try testing.expectEqual(ui.Layer.State.unavailable, dev.state);
    try testing.expect(!dev.blocks);
    try testing.expectEqualStrings("DEGRADED", wordFor(dev));
    // And the row that really stops the run keeps the word, so this is not a
    // report that gave up saying `BLOCKED` at all.
    try testing.expectEqualStrings("BLOCKED", wordFor(rowNamed(rows, "credential").?));

    // A layer the machine does not have and a session cannot start without is
    // the same fault pointing the other way: the column said `NONE`, which
    // reads as nothing to configure, while the footer counted the row.
    var no_landlock = healthy();
    no_landlock.landlock = .{ .absent = "the kernel answered that it has no Landlock" };
    no_landlock.landlock_abi = null;
    const kernel_rows = try rowsFor(arena, no_landlock);
    const landlock = rowNamed(kernel_rows, "landlock").?;
    try testing.expectEqual(ui.Layer.State.unsupported, landlock.state);
    try testing.expect(landlock.blocks);
    try testing.expectEqualStrings("BLOCKED", wordFor(landlock));
}

test "the printed report says BLOCKED as many times as its own footer counts" {
    // The whole point, read the way a person reads it: the column and the last
    // line of the report, in one capture. The rows are Darwin's, because that
    // is the machine the two answers were seen to disagree on.
    //
    // Mutation check: make `wordFor` ignore `blocks` and the count below is
    // two while the footer still says one.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = Measured{
        .driver = sandbox.darwin_driver_for_testing.guarantees,
        .family = .seatbelt,
        .seatbelt = .ok,
        .rlimits = .ok,
    };
    m.git_program = "/usr/bin/git";
    m.nix_program = "/run/current-system/sw/bin/nix";
    m.toolchain = .{ .host = 4 };
    m.cache = .ok;
    m.free_bytes = 8 * 1024 * 1024 * 1024;
    m.dev_shell = .{ .failed = "nix could not evaluate it" };
    m.credential = .{ .unconfigured = "no provider is named in config.zon" };

    const rows = try rowsFor(arena, m);
    const verdict = verdictFor(rows);
    try testing.expectEqual(Verdict.blocked, verdict);

    tty.configure(.{});
    defer tty.configure(.{});

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    printReport("/some/project", m, rows, verdict);
    tty.flushOut();

    // The word appears in no sentence of this report, so counting it counts
    // the column.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, said.out(), "BLOCKED"));
    try testing.expectEqual(countBlocking(rows), std.mem.count(u8, said.out(), "BLOCKED"));
    try testing.expect(std.mem.indexOf(u8, said.err(), "Rows that stop a first run: 1 of") != null);
    // And the row that does not stop the run is still in the column, saying
    // what the session loses.
    try testing.expect(std.mem.indexOf(u8, said.out(), "DEGRADED") != null);
}

test "a machine where no tool call could work does not read as a machine a session can start on" {
    // The fault this row exists for. Measured on 2026-08-25 on a bare Debian
    // with no Nix: every row passed, the session started, and the first tool
    // call died in the mount tree because the one thing to bind was not there.
    //
    // Mutation check: set `blocks` to false on the `toolchain` row and the
    // verdict below reads `degraded`, which is the report that lied.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.toolchain = .none;
    const rows = try rowsFor(arena, m);
    try testing.expect(rowNamed(rows, "toolchain").?.blocks);
    try testing.expectEqual(Verdict.blocked, verdictFor(rows));

    // The fallback is not a fault. A machine that mounts its own system
    // directories runs, and the row says so and says how to narrow it.
    m.toolchain = .{ .host = 6 };
    const wide = try rowsFor(arena, m);
    const row = rowNamed(wide, "toolchain").?;
    try testing.expectEqual(ui.Layer.State.on, row.state);
    try testing.expect(!row.blocks);
    try testing.expect(std.mem.indexOf(u8, row.fix, "flake.nix") != null);
    try testing.expectEqual(Verdict.ready, verdictFor(wide));

    // An image the project names and this machine does not have is a refusal
    // before a session starts, never a fault at the first tool call.
    m.toolchain = .{ .image_unusable = "run `docker pull debian:stable-slim` first" };
    const missing = try rowsFor(arena, m);
    try testing.expect(rowNamed(missing, "toolchain").?.blocks);
    try testing.expectEqual(Verdict.blocked, verdictFor(missing));
}

test "the container row appears only where it matters, and its trust position is never a layer" {
    // **The row must add nothing to the guarantee columns.** A root daemon is
    // a weaker trust position and not a broken sandbox, so it reads `OK` with
    // a warning line beside it.
    //
    // Mutation check: give the `.ready` arm `.state = .unavailable` for a
    // privileged trust and the first verdict below reads `degraded`.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.container = .{ .ready = .{ .kind = .docker, .program = "/usr/bin/docker", .trust = .root_daemon } };
    const with_docker = try rowsFor(arena, m);
    const row = rowNamed(with_docker, "container runtime").?;
    try testing.expectEqual(ui.Layer.State.on, row.state);
    try testing.expect(!row.blocks);
    try testing.expect(std.mem.indexOf(u8, row.fix, "Warning") != null);
    try testing.expectEqual(Verdict.ready, verdictFor(with_docker));
    // And the guarantee set is untouched by any of it: the fixture still states
    // the machine whose rows this test read.
    //
    // **Stated, and never `sandbox.Sandbox.guarantees`.** `healthy()` is a
    // Linux machine on every host, and the Darwin driver gives four of the six
    // guarantees, so reading this build's own driver here asked a Mac to answer
    // for a Linux row and failed there and only there.
    //
    // Mutation check: give `healthy()` the Darwin driver's own guarantees, or a
    // `.family` of `.seatbelt`, and this fails on either half.
    try testing.expectEqual(healthy().family, LayerFamily.forDriver(healthy().driver));

    // A rootless runtime gets no warning line at all.
    m.container = .{ .ready = .{ .kind = .podman, .program = "/usr/bin/podman", .trust = .user_only } };
    const rootless = try rowsFor(arena, m);
    try testing.expectEqual(@as(usize, 0), rowNamed(rootless, "container runtime").?.fix.len);

    // **A machine that needs no runtime gains no row.** Most machines have
    // none and most projects name no image, and a yellow row about a thing
    // nobody asked for teaches a person to stop reading the report.
    m.container = .not_installed;
    const quiet = try rowsFor(arena, m);
    try testing.expectEqual(@as(?Row, null), rowNamed(quiet, "container runtime"));

    m.container = .{ .unreachable_runtime = "the daemon is not running" };
    const silent = try rowsFor(arena, m);
    try testing.expectEqual(@as(?Row, null), rowNamed(silent, "container runtime"));

    // Until the project names an image, and then both of those matter.
    m.toolchain = .{ .image_unusable = "no container runtime is installed" };
    m.container = .not_installed;
    const wanted = try rowsFor(arena, m);
    try testing.expectEqual(ui.Layer.State.off, rowNamed(wanted, "container runtime").?.state);
    // The toolchain row is what refuses. The runtime row states a fact.
    try testing.expect(!rowNamed(wanted, "container runtime").?.blocks);
    try testing.expect(rowNamed(wanted, "toolchain").?.blocks);
}

test "a build whose driver applies no layer gets one sentence and no layer rows" {
    // A build with no driver at all. A column of six `unsupported` rows reads
    // as a machine that is nearly ready and needs a setting changed. Such a
    // build refuses outright, and no row of a table says that.
    //
    // Mutation check: drop the `m.family` guard in `rowsFor` and the layer rows
    // come back, which is exactly the column this test forbids.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = Measured{ .driver = sandbox.Sandbox.Guarantees.initEmpty(), .family = .none };
    m.credential = .{ .found = "chock login" };
    m.cache = .ok;
    m.free_bytes = 8 * 1024 * 1024 * 1024;
    m.dev_shell = .no_flake;

    const rows = try rowsFor(arena, m);

    for ([_][]const u8{
        "user namespace",
        "mount namespace",
        "pid namespace",
        "ipc namespace",
        "net namespace",
        "landlock",
        "seccomp",
        "pidfd",
        "disk cap tmpfs",
        "overlayfs",
        "cgroup v2",
    }) |name| {
        try testing.expectEqual(@as(?Row, null), rowNamed(rows, name));
    }

    // The rows that are true of the machine whatever the driver does are still
    // there, because a person on such a build still wants to know them.
    try testing.expect(rowNamed(rows, "credential") != null);
    try testing.expect(rowNamed(rows, "workspace space") != null);

    // The sentence names the call that refuses and says there is no setting,
    // so nobody spends an afternoon looking for one.
    try testing.expect(std.mem.indexOf(u8, refuses_outright, "Sandbox.spawn refuses") != null);
    try testing.expect(std.mem.indexOf(u8, refuses_outright, "no sandbox driver") != null);
    try testing.expect(std.mem.indexOf(u8, refuses_outright, "nothing to configure") != null);
}

test "the real Darwin driver gives four layers, and still refuses a root of its own" {
    // **The gate on what this command tells a person about a Mac.** The Darwin
    // driver applies Seatbelt for paths, the network, signals and IPC, and each
    // of the four is broken against on a real Mac by a test in
    // `test/sandbox/darwin_escape.zig`. `chock-sandbox.zig` exports that driver
    // on every host for exactly this kind of check.
    //
    // Mutation check: add `.syscall_restricted` to the Darwin driver's own
    // `guarantees` and this fails on the count, which is the layer measured on
    // 2026-08-25 to compile, apply and do nothing.
    const darwin = sandbox.darwin_driver_for_testing;
    try testing.expectEqual(@as(usize, 4), darwin.guarantees.count());
    for ([_]sandbox.Sandbox.Guarantee{ .network_isolated, .signal_isolated, .ipc_isolated, .path_restricted }) |one| {
        try testing.expect(darwin.guarantees.contains(one));
    }
    // The two that stay off, because nothing enforces either.
    try testing.expect(!darwin.guarantees.contains(.syscall_restricted));
    try testing.expect(!darwin.guarantees.contains(.workspace_mounted));

    // And the refusal is unchanged: macOS cannot pivot into a root of its own,
    // so a config that asks for one gets nothing rather than a tree that was
    // never built.
    try testing.expectError(error.NoMountNamespace, darwin.spawn(
        testing.allocator,
        .{ .root = "/nonexistent", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} },
        &.{"true"},
        null,
        null,
    ));

    // That driver belongs to the Seatbelt family, which is what gives a Mac its
    // own rows rather than a column of Linux mechanisms it has never had.
    try testing.expectEqual(LayerFamily.seatbelt, LayerFamily.forDriver(darwin.guarantees));
}

test "a seatbelt build gets darwin's own rows, and none of the eleven linux ones" {
    // Mutation check: change the `m.family == .seatbelt` guard in `rowsFor` to
    // `.namespaces` and the loop below finds `landlock`, which is a mechanism
    // no Mac has ever had.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = Measured{
        .driver = sandbox.darwin_driver_for_testing.guarantees,
        .family = .seatbelt,
        .seatbelt = .ok,
        .rlimits = .ok,
    };
    m.credential = .{ .found = "chock login" };
    m.cache = .ok;
    m.free_bytes = 8 * 1024 * 1024 * 1024;
    m.dev_shell = .no_flake;
    // A Mac with git and with the host's own system directories, which is
    // every Mac. Neither row belongs to a layer family, so both are here to
    // keep this test about the Darwin rows and about nothing else.
    m.git_program = "/usr/bin/git";
    m.toolchain = .{ .host = 4 };
    m.tool_call_refused = "a tool call needs a path to appear somewhere else";

    const rows = try rowsFor(arena, m);

    for ([_][]const u8{ "user namespace", "mount namespace", "landlock", "seccomp", "pidfd", "cgroup v2", "overlayfs" }) |name| {
        try testing.expectEqual(@as(?Row, null), rowNamed(rows, name));
    }
    // The four this driver really applies, all on.
    for ([_][]const u8{ "seatbelt", "network", "signal reach", "ipc" }) |name| {
        try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, name).?.state);
    }
    // The four limits with no Darwin mechanism read `NONE`, never `BLOCKED`:
    // there is nothing to configure and no version of macOS closes any of them.
    for ([_][]const u8{ "memory ceiling", "mapped memory", "process count", "disk cap tmpfs" }) |name| {
        const row = rowNamed(rows, name).?;
        try testing.expectEqual(ui.Layer.State.unsupported, row.state);
        try testing.expect(!row.blocks);
        try testing.expect(row.means.len != 0);
    }
    // The three limits Darwin does honour are one row, and it is on.
    try testing.expectEqual(ui.Layer.State.on, rowNamed(rows, "rlimit floor").?.state);

    // The row that decides the answer. Every layer above is on and a session
    // still starts nothing, so the verdict is blocked and not degraded.
    const tool_call = rowNamed(rows, tool_call_name).?;
    try testing.expect(tool_call.blocks);
    try testing.expectEqual(Verdict.blocked, verdictFor(rows));

    // And when a tool call really runs, the same rows read ready.
    m.tool_call_refused = null;
    const runs = try rowsFor(arena, m);
    try testing.expectEqual(ui.Layer.State.on, rowNamed(runs, tool_call_name).?.state);
    try testing.expectEqual(Verdict.degraded, verdictFor(runs));
}

test "the tool call row asks the libraries where they really put their paths" {
    // **Two answers, one per build, and both are read from `chock-core` rather
    // than spelled here.** A build that moves a path still asks for the runtime
    // prefix, so the row is still refused and still names the path. A build
    // that moves none leaves the scratch area, the cache and the task list
    // where they are, so the config binds each source to itself, the driver
    // expresses it, and the row is on.
    //
    // Mutation check on Darwin: put the bare `sandbox_dir` values back in
    // `seatbeltToolCallRefusal` and the null below is a refusal instead, which
    // is `chock doctor` telling every Mac a session cannot start.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = "/some/session/scratch";
    if (sandbox.expresses.moved_paths) {
        const why = seatbeltToolCallRefusal(arena, root).?;
        try testing.expect(std.mem.indexOf(u8, why, "bind mount") != null);
        try testing.expect(std.mem.indexOf(u8, why, chock_core.scratchpad.sandbox_dir) != null);
    } else {
        try testing.expectEqual(@as(?[]const u8, null), seatbeltToolCallRefusal(arena, root));
        // The three really are the host path on this build, so the line above
        // is about what the libraries answer and not about a probe that asked
        // for nothing.
        for ([_][]const u8{
            chock_core.scratchpad.sandboxDirFor(root),
            chock_core.cache.sandboxDirFor(root),
            chock_core.tasks.sandboxDirFor(root),
        }) |target| try testing.expectEqualStrings(root, target);
    }

    // A config that asks for no moved path is not refused, so the checks above
    // are about the paths and not about the platform.
    try testing.expectEqual(
        @as(?sandbox.darwin_driver_for_testing.Inexpressible, null),
        sandbox.darwin_driver_for_testing.expressibleOn(.{
            .root = "/",
            .mounts = &.{.{ .bind = .{ .source = "/x", .target = "/x", .read_only = true } }},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
        }),
    );
    // And one that does is refused, so a Darwin build's null above is a real
    // measurement and not a driver that accepts everything.
    try testing.expectEqual(
        @as(?sandbox.darwin_driver_for_testing.Inexpressible, .bind_moves_a_path),
        sandbox.darwin_driver_for_testing.expressibleOn(.{
            .root = "/",
            .mounts = &.{.{ .bind = .{ .source = "/x", .target = "/y", .read_only = true } }},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
        }),
    );
}

test "the exit code says whether a first run can work here, and degraded is not a failure" {
    // Mutation check: return `.blocked` for any row that is not on and the
    // degraded case below exits 2, which fails every healthy NixOS machine
    // whose init system delegates nothing.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ready = try rowsFor(arena, healthy());
    try testing.expectEqual(Verdict.ready, verdictFor(ready));
    try testing.expectEqual(@as(u8, 0), exitFor(verdictFor(ready)).code());

    var degraded = healthy();
    degraded.cgroup = .{ .unavailable = .no_delegated_parent };
    degraded.overlayfs = .{ .absent = "the kernel answered that it does not have it" };
    degraded.nix_program = null;
    const degraded_rows = try rowsFor(arena, degraded);
    try testing.expectEqual(Verdict.degraded, verdictFor(degraded_rows));
    try testing.expectEqual(@as(u8, 0), exitFor(verdictFor(degraded_rows)).code());

    var blocked = healthy();
    blocked.landlock = .{ .absent = "the kernel answered that it has no Landlock" };
    blocked.landlock_abi = null;
    const blocked_rows = try rowsFor(arena, blocked);
    try testing.expectEqual(Verdict.blocked, verdictFor(blocked_rows));
    try testing.expectEqual(Exit.faulted, exitFor(verdictFor(blocked_rows)));
    try testing.expect(exitFor(verdictFor(blocked_rows)).code() != 0);
    // Never `usage`: that code already means the command line was wrong, and
    // a script that read the two the same way would answer a broken machine
    // by printing its own help.
    try testing.expect(exitFor(verdictFor(blocked_rows)) != .usage);
}

/// A machine on which every row is in its failing form, so `Row.blocks` is a
/// decision on every row rather than a default nobody set.
fn broken() Measured {
    var m = healthy();
    const refused = Probe{ .refused = "the kernel refused it to this process" };
    m.user_namespace = refused;
    m.mount_namespace = refused;
    m.pid_namespace = refused;
    m.ipc_namespace = refused;
    m.network_namespace = refused;
    m.landlock = .{ .absent = "the kernel answered that it has no Landlock" };
    m.landlock_abi = null;
    m.seccomp = refused;
    m.cgroup = .{ .unavailable = .no_delegated_parent };
    m.overlayfs = .{ .absent = "the kernel answered that it does not have it" };
    m.pidfd = refused;
    m.tmpfs = refused;
    m.git_program = null;
    m.nix_program = null;
    m.dev_shell = .{ .failed = "flake.nix does not evaluate" };
    // A runtime that is there and did not answer, so the row exists and is
    // not on. A machine with none gets no row at all: see `containerRow`.
    m.container = .{ .unreachable_runtime = "the daemon is not running" };
    m.toolchain = .none;
    m.credential = .{ .unconfigured = "there is no configuration" };
    m.cache = .{ .refused = "CacheDirectoryUnwritable" };
    // Read, and under the floor. The reading that failed is a different fact
    // and the test below states it separately.
    m.free_bytes = 1024;
    m.card_seal = .{ .absent = "there is no pcscd socket at /run/pcscd/pcscd.comm" };
    m.card_readers = null;
    // The project asked to give up the write and execute rule. The failing
    // form of this row is not a machine that cannot hold it: every machine can,
    // and only a project's own policy takes it away. See `measureHardening`.
    m.write_execute = .relaxed;
    return m;
}

test "every row that stops a first run is one Sandbox.spawn or chock run really refuses on" {
    // The list is a claim about other files, so it is written out here where
    // somebody changing one of them will meet it. Measured on a machine where
    // every row failed, so `blocks` is a decision on each one.
    //
    // Mutation check: mark the cgroup row blocking and this fails, which is
    // what stops a best effort layer quietly becoming a requirement.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rows = try rowsFor(arena, broken());
    for (rows) |row| try testing.expect(row.state != .on);

    const blocking = [_][]const u8{
        // Every one of these is a `SetupError` or a `SpawnError` member.
        "user namespace",
        "mount namespace",
        "pid namespace",
        "ipc namespace",
        "net namespace",
        "landlock",
        "seccomp",
        "pidfd",
        "disk cap tmpfs",
        // `chock run` reports and returns before a session starts.
        "credential",
        // The workspace of every session is a worktree, and `git` is what
        // makes one. Measured: with no git, `chock run` answers "the
        // workspace for /proj could not be built: NotFound".
        "git",
        // There is nothing for a tool call to run a program from, so the
        // session would start and every call in it would fail in the mount
        // tree. `toolchainFor` refuses at session start instead.
        "toolchain",
        // Every writing tool call is refused under the floor, so the session
        // starts and gets nothing done.
        "workspace space",
    };
    const not_blocking = [_][]const u8{
        // Only a project with no git of its own needs an overlay.
        "overlayfs",
        // The rlimit floor still applies, by `chock-sandbox`'s own decision.
        "cgroup v2",
        // Both are a warning in `src/run.zig` and not a refusal.
        "nix",
        "dev shell",
        "toolchain cache",
        // `seal.Level` has a software key for exactly this, and it records
        // which level it used inside the bytes the signature covers.
        "card seal",
        // W^X is documented hardening and it is not a boundary, so a project
        // that gave it up gets a session and gets told. `test/redteam/scope.zig`
        // retires it by name, and `lib/chock-sandbox/linux/seccomp.zig` names
        // three measured ways past it.
        "write^execute",
    };
    for (blocking) |name| try testing.expect(rowNamed(rows, name).?.blocks);
    for (not_blocking) |name| try testing.expect(!rowNamed(rows, name).?.blocks);
    try testing.expectEqual(blocking.len + not_blocking.len, rows.len);
}

test "a provider that asks for no credential is not a machine that cannot run" {
    // `chock_auth.lookup.Source.none` is not an error: a local llama.cpp asks
    // for nothing. A report that read an absent credential as a fault would
    // refuse every local endpoint.
    //
    // Mutation check: treat `.not_needed` as `.unconfigured` and this exits 2
    // on a working local setup.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.credential = .not_needed;
    const rows = try rowsFor(arena, m);
    try testing.expect(!rowNamed(rows, "credential").?.blocks);
    try testing.expectEqual(Verdict.degraded, verdictFor(rows));
    try testing.expectEqual(@as(u8, 0), exitFor(verdictFor(rows)).code());
}

test "free space that could not be read is never reported as no room" {
    // The direction of the error matters: an unreadable filesystem refuses
    // nothing, and a report that read null as zero would tell every user in a
    // container that their disk is full.
    //
    // Mutation check: read `free_bytes orelse 0` and this row starts blocking.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var unknown = healthy();
    unknown.free_bytes = null;
    const unknown_rows = try rowsFor(arena, unknown);
    const unknown_row = rowNamed(unknown_rows, "workspace space").?;
    try testing.expect(!unknown_row.blocks);
    try testing.expect(std.mem.indexOf(u8, unknown_row.means, "not the same as no room") != null);

    // And a real reading under the floor does block, so the branch above is a
    // decision and not a row that can never fail.
    var full = healthy();
    full.free_bytes = 1024;
    const full_rows = try rowsFor(arena, full);
    try testing.expect(rowNamed(full_rows, "workspace space").?.blocks);
    try testing.expectEqual(Verdict.blocked, verdictFor(full_rows));
}

test "an audit sink this installation requires and cannot reach is reported and stops nothing" {
    // **The whole point of the row.** A machine that cannot reach the sink its
    // installation requires is exactly the thing somebody wants to know before
    // a session, and it is not a reason to refuse one:
    // `lib/chock-policy/org.zig` weighed refusing to start and rejected it,
    // because an organisation's control that becomes an outage sends the
    // developer to a tool that is not Chock, and then the organisation gets no
    // record at all rather than a late one.
    //
    // Mutation check: set `blocks` on this row and the verdict below becomes
    // `blocked` and the exit code 2, which is the refuse-to-start answer coming
    // back through the exit status.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = healthy();
    m.required_sinks = &.{.{
        .kind = .directory,
        .path = "/var/audit/chock",
        .reached = .{ .refused = "AccessDenied" },
    }};
    const rows = try rowsFor(arena, m);

    const row = rowNamed(rows, required_sink_name).?;
    try testing.expect(!row.blocks);
    try testing.expectEqual(ui.Layer.State.unavailable, row.state);
    // The path an organisation wrote, so a reader knows which place is out of
    // reach, and the fault, so they know what to fix.
    try testing.expect(std.mem.indexOf(u8, row.means, "/var/audit/chock") != null);
    try testing.expect(std.mem.indexOf(u8, row.means, "AccessDenied") != null);
    // And both halves of what it costs: the session runs, and the exit code it
    // ends with when the tail never leaves. The number comes from `Exit`, so it
    // cannot drift away from the code a script reads.
    try testing.expect(std.mem.indexOf(u8, row.means, "still starts") != null);
    const code = try std.fmt.allocPrint(arena, "exits {d}", .{Exit.audit_gap.code()});
    try testing.expect(std.mem.indexOf(u8, row.means, code) != null);
    // Nobody typed this sink, so the fix must not send a reader to a command
    // line that does not hold it.
    try testing.expect(std.mem.indexOf(u8, row.fix, "org policy bundle") != null);

    // Degraded at worst, and a script still reads zero.
    try testing.expectEqual(Verdict.degraded, verdictFor(rows));
    try testing.expectEqual(@as(u8, 0), exitFor(verdictFor(rows)).code());

    // It belongs under the first run heading, because that is the half about
    // whether a session can start well here rather than about the sandbox.
    try testing.expect(isFirstRunRow(row));
}

test "a required sink that was reached says so, and an installation with no bundle adds no row" {
    // Two facts one measurement each. A sink that answered has to read as on,
    // or the row would be a warning that fires on every managed installation
    // and nobody would read it by the second week. And an installation nobody
    // gave a bundle must gain nothing at all, which is what keeps every machine
    // that predates required sinks reading exactly as it did.
    //
    // Mutation check: build a row for an installation with no required sink and
    // the second half fails. Drop the reached branch of `requiredSinkRow` and
    // the first half fails, because a sink that answered would then carry a fix
    // and a reason, which is the warning on every managed machine.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var reached = healthy();
    reached.required_sinks = &.{
        .{ .kind = .directory, .path = "/var/audit/chock", .reached = .ok },
        .{ .kind = .syslog, .path = "/dev/log", .reached = .ok },
    };
    const reached_rows = try rowsFor(arena, reached);

    // One row each, in the order the bundle names them, and both on.
    var found: usize = 0;
    for (reached_rows) |row| {
        if (!std.mem.eql(u8, row.name, required_sink_name)) continue;
        try testing.expectEqual(ui.Layer.State.on, row.state);
        try testing.expectEqualStrings("", row.fix);
        found += 1;
    }
    try testing.expectEqual(@as(usize, 2), found);
    try testing.expect(std.mem.indexOf(u8, reached_rows[reached_rows.len - 2].means, "/var/audit/chock") != null);
    try testing.expect(std.mem.indexOf(u8, reached_rows[reached_rows.len - 1].means, "/dev/log") != null);
    // Every row on, so a managed machine that is well is ready and not
    // degraded.
    try testing.expectEqual(Verdict.ready, verdictFor(reached_rows));

    // And the installation nobody gave a bundle. `Measured.required_sinks`
    // defaults to empty, which is the same value a bundle requiring none gives.
    const plain = try rowsFor(arena, healthy());
    try testing.expectEqual(@as(?Row, null), rowNamed(plain, required_sink_name));
    try testing.expectEqual(reached_rows.len - 2, plain.len);
}

test "a daemon that refused is DEGRADED and a machine with no reader is NONE" {
    // The two ends of the card seal row, and the pair `chock-pcsc` was given
    // two errors for. A daemon that accepted the connection and said no is a
    // polkit rule an administrator can change, which is what `unavailable`
    // means everywhere else in this report. A daemon that answered and named no
    // reader is a reader somebody has to plug in, and there is nothing to
    // configure.
    //
    // Mutation check: map `Probe.refused` to `.unsupported` in `cardSealRow`
    // and the first expectation flips, which would tell a person with a
    // reachable daemon to go and install one.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var refused = healthy();
    refused.card_seal = .{ .refused = "pcscd accepted the connection and closed it without answering" };
    refused.card_readers = null;
    const refused_rows = try rowsFor(arena, refused);
    const refused_row = rowNamed(refused_rows, "card seal").?;
    try testing.expectEqual(ui.Layer.State.unavailable, refused_row.state);
    try testing.expect(std.mem.indexOf(u8, refused_row.means, "closed it without answering") != null);
    // The word says what the session loses and never that it stops, because
    // this row stops nothing: see the two assertions at the end.
    try testing.expectEqualStrings("DEGRADED", wordFor(refused_row));

    var empty = healthy();
    empty.card_seal = .{ .absent = "a PC/SC daemon answered and no reader is attached" };
    empty.card_readers = 0;
    const empty_rows = try rowsFor(arena, empty);
    const empty_row = rowNamed(empty_rows, "card seal").?;
    try testing.expectEqual(ui.Layer.State.unsupported, empty_row.state);
    try testing.expectEqualStrings("NONE", wordFor(empty_row));

    // **Neither stops a first run.** `seal.Level` already has a software key
    // for exactly this, and it records that it used one. A doctor that exited 2
    // over a missing reader would refuse to start a session over a fallback the
    // design made on purpose.
    try testing.expect(!refused_row.blocks);
    try testing.expect(!empty_row.blocks);
    try testing.expectEqual(Verdict.degraded, verdictFor(refused_rows));
    try testing.expectEqual(@as(u8, 0), exitFor(verdictFor(refused_rows)).code());
}

test "a card seal row that is on says how many readers were named" {
    // The count comes from the measurement and not from the state. A row that
    // said "a reader is attached" without the number would read the same on a
    // machine with one reader and on a machine with five.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var three = healthy();
    three.card_readers = 3;
    const rows = try rowsFor(arena, three);
    const row = rowNamed(rows, "card seal").?;
    try testing.expectEqual(ui.Layer.State.on, row.state);
    try testing.expect(std.mem.indexOf(u8, row.means, "3 reader") != null);
    // Nothing to do about a row that is on.
    try testing.expectEqualStrings("", row.fix);
}

test "the card seal is reported before a first run, not as a sandbox layer" {
    // It is not a layer: it protects nothing about a tool call, and a column of
    // sandbox layers with a smart card in it reads as a boundary that is not
    // there.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rows = try rowsFor(arena, healthy());
    try testing.expect(isFirstRunRow(rowNamed(rows, "card seal").?));
}

test "the report opens with the version, on an ordinary run and not only with --verbose" {
    // **The one line that makes a pasted report answerable.** A person reports
    // a fault by pasting this command's output, and a report with no build in
    // it costs a round trip every time. The verbosity pass moved every
    // rationale to `--verbose`; this is an answer rather than a teaching, so it
    // stays on the default output.
    //
    // Mutation check: send the line through `tty.detail` and the default run
    // below loses it; drop it altogether and both halves fail.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const m = healthy();
    const rows = try rowsFor(arena, m);

    tty.configure(.{});
    defer tty.configure(.{});

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    printReport("/some/project", m, rows, verdictFor(rows));
    tty.flushOut();

    // The whole line, and the first line: `indexOf` would pass for a version
    // buried beside the last row, where nobody pastes from.
    const first = std.mem.sliceTo(said.out(), '\n');
    try testing.expectEqualStrings(version_line, first);
    // On standard output with the rows, because `chock doctor > report.txt` is
    // how a report is kept, and a version on the other stream would not be in
    // the file.
    try testing.expect(std.mem.indexOf(u8, said.err(), version_line) == null);
    // And it is above every row.
    try testing.expect(std.mem.indexOf(u8, said.out(), first_run_heading).? > first.len);
}

test "the report says what redaction is not, with --verbose, in the words the module argued for" {
    // **Byte for byte, and this is why the constant exists.**
    // `chock_core.redact.not_a_boundary` is held beside the mechanism so that a
    // command showing it to a person shows what that module argued for, and not
    // a paraphrase that got friendlier over time. This project has watched
    // prose expire five times.
    //
    // Mutation check: reword one character of the sentence in `printReport`,
    // or summarise it, and this fails.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const m = healthy();
    const rows = try rowsFor(arena, m);

    // An ordinary run says nothing about redaction at all.
    {
        tty.configure(.{});
        defer tty.configure(.{});

        var quiet: tty.Capture = undefined;
        quiet.start(testing.io, testing.allocator);
        defer quiet.stop(testing.io);

        printReport("/some/project", m, rows, verdictFor(rows));
        tty.flushOut();

        try testing.expect(std.mem.indexOf(u8, quiet.out(), "Redaction") == null);
    }

    tty.configure(.{ .verbose = true });
    defer tty.configure(.{});

    // Captured rather than let through, so the report is read here instead of
    // scrolling past in a build log: see `tty.Capture` and `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    printReport("/some/project", m, rows, verdictFor(rows));
    tty.flushOut();

    try testing.expect(std.mem.indexOf(u8, said.out(), chock_core.redact.not_a_boundary) != null);
    // On standard output with the rows, because it is part of the answer once a
    // person asks for it, and not a diagnostic.
    //
    // The project path is on standard error, because `tty.detail` is where
    // every other `--verbose` line goes, so the rows a pipe reads are rows.
    try testing.expect(std.mem.indexOf(u8, said.err(), "/some/project") != null);
    // After both headings, so a reader meets it once they have the report and
    // not before they have read a single row.
    const at = std.mem.indexOf(u8, said.out(), chock_core.redact.not_a_boundary).?;
    try testing.expect(at > std.mem.indexOf(u8, said.out(), layers_heading).?);
    try testing.expect(at > std.mem.indexOf(u8, said.out(), first_run_heading).?);
    // And it is not a row: no glyph, no word, and no name column beside it.
    try testing.expect(std.mem.indexOf(u8, said.out(), "redaction   ") == null);
}

test "a required sink is reached through the shipper's own transport, and the probe is removed" {
    // **Measured, never worked out.** The reach is
    // `chock_proto.ship.Sink.reach`, the transport a session ships through, so
    // this command states no second open and no second connect. Driven against
    // a real directory and a real path with no socket at it.
    //
    // Mutation check: drop the `deleteFile` in `reachSink` and the directory
    // below is left holding a file this command made, which a collector
    // watching it would read.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = buffer[0..len];

    // A directory a collector would watch, which this command makes rather than
    // requires, exactly as a session does.
    const drop_dir = try std.fmt.allocPrint(arena, "{s}/audit", .{root});
    const reached = reachSink(arena, testing.io, .{ .kind = .directory, .path = drop_dir });
    try testing.expectEqual(ui.Layer.State.on, reached.state());

    // The directory is there and holds nothing at all: the probe opened a file
    // and removed it, and it sent no record, so a collector reads no session
    // that never ran.
    var opened = try std.Io.Dir.openDirAbsolute(testing.io, drop_dir, .{ .iterate = true });
    defer opened.close(testing.io);
    var it = opened.iterate();
    try testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(testing.io));

    // A syslog path with nothing at it is the answer a required sink that is
    // down gives, and it is `unavailable` and not `unsupported`: a daemon that
    // is not running is something an administrator changes.
    const missing = try std.fmt.allocPrint(arena, "{s}/no-such-socket", .{root});
    const down = reachSink(arena, testing.io, .{ .kind = .syslog, .path = missing });
    try testing.expectEqual(ui.Layer.State.unavailable, down.state());
    try testing.expect(down.why().len != 0);
}

test "the command line takes a project and nothing else" {
    try testing.expectEqual(@as(?[]const u8, null), (try parseOptions(&.{})).project);
    try testing.expectEqualStrings("/somewhere", (try parseOptions(&.{ "--project", "/somewhere" })).project.?);
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"list"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"-h"}));
}

test "the probe answers map to the three states and never invent a fourth" {
    // A kernel that says "no such mechanism" is a fact about the machine; a
    // kernel that refuses this process is a fact about this process. Reading
    // both as the same thing is what makes a report useless.
    try testing.expectEqual(ui.Layer.State.on, whyFor(.ok, "x").state());
    try testing.expectEqual(ui.Layer.State.unsupported, whyFor(.absent, "x").state());
    try testing.expectEqual(ui.Layer.State.unavailable, whyFor(.refused, "x").state());
    try testing.expectEqualStrings("x", whyFor(.refused, "x").why());
    try testing.expectEqualStrings("", whyFor(.ok, "x").why());
}

test "a record from the probe pipe with a byte that names no step is dropped" {
    // The bytes come from another process, so they are read with `fromInt`
    // and never with `@enumFromInt`, which is undefined behaviour on an
    // invalid tag.
    try testing.expectEqual(@as(?Step, null), std.enums.fromInt(Step, 0));
    try testing.expectEqual(@as(?Step, null), std.enums.fromInt(Step, 200));
    try testing.expectEqual(Step.namespaces, std.enums.fromInt(Step, 1).?);
    try testing.expectEqual(@as(?Answer, null), std.enums.fromInt(Answer, 9));
    try testing.expectEqual(Answer.ok, std.enums.fromInt(Answer, 0).?);
}
