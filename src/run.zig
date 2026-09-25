//! `chock run`: one agent session against the project in the current
//! directory, from the command line, with no interface. The run is three
//! phases, each with the `std.Io` its own job needs, one at a time.

const std = @import("std");
const builtin = @import("builtin");
const chock_auth = @import("chock-auth");
const chock_broker = @import("chock-broker");
const chock_container = @import("chock-container");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const chock_cost = @import("chock-cost");
const chock_nix = @import("chock-nix");
const chock_proto = @import("chock-proto");
const chock_provider = @import("chock-provider");
const chock_workspace = @import("chock-workspace");
const sandbox = @import("chock-sandbox");

const subagent = chock_core.subagent;

const approval = @import("approval.zig");
const clock = @import("clock.zig");
const sessions_cmd = @import("sessions.zig");
const tty = @import("tty.zig");
const interrupt = @import("interrupt.zig");
const handover = @import("handover.zig");
const session_paths = @import("session.zig");
const ui = @import("ui.zig");
const Exit = @import("main.zig").Exit;
const exitFor = @import("main.zig").exitFor;

const usage_text =
    \\Usage: chock run [options] [message...]
    \\
    \\With no message on the command line, the message is read from standard input.
    \\
    \\Options:
    \\  --provider <name>   The provider instance to talk to, by its name in the
    \\                      configuration. Defaults to .defaults.provider, or to the
    \\                      only instance when the configuration has exactly one.
    \\  --model <id>        The model on the wire. Defaults to .defaults.model.
    \\  --project <dir>     The project. Defaults to the current directory.
    \\  --allow-dirty       Copy the project's uncommitted work into the workspace.
    \\                      Without this the agent sees the committed state.
    \\  --dev-shell <name>  The devShells attribute the tool environment comes
    \\                      from, for this run. Defaults to .nix.dev_shell, and
    \\                      to what `nix develop` takes when neither names one.
    \\  --policy-rule <r>   One policy rule, written <action>=<decision>. It
    \\                      answers instead of the project's chock.zon, and the
    \\                      org bundle still holds it. Repeatable.
    \\  --continue          Continue the newest session of this project.
    \\  --session <id>      Continue this session.
    \\  --adopt             Become the owner of a session that already exists and
    \\                      carry on from what its log holds, with no new message.
    \\                      Needs --session or --continue. This is what
    \\                      `chock detach` asks the daemon to do.
    \\  --agent-kind <kind> The agent kind that selects the policy. Defaults to "main".
    \\  --instructions <path>
    \\                      Read this file and put it in the prompt as instructions
    \\                      for this session. Give it more than once for more than
    \\                      one file. The agent is told a person named the file on
    \\                      the command line, so it weighs it as your own words and
    \\                      not as the project's. It adds to AGENTS.md rather than
    \\                      replacing it, and a file that cannot be read stops the
    \\                      session.
    \\  --org-bundle <path> Use this org policy bundle instead of the one this
    \\                      installation holds. The bundle is the layer above
    \\                      chock.zon, and chock.zon may only narrow it. A bundle
    \\                      that has already expired is refused here; one already
    \\                      installed keeps binding whatever its date says.
    \\  --max-turns <n>     Stop after this many turns. Off by default: a session
    \\                      runs until the agent is done, and stops on its own when
    \\                      it repeats the same call over and over.
    \\  --no-notices        Do not tell the agent what the harness knows: the time,
    \\                      the task restated, a call it has already made, a file it
    \\                      has already read, the budget, and the work it cannot see.
    \\                      For measuring whether any of that helps.
    \\  --export-dir <dir>  Ship the session log into this directory as it is
    \\                      written, one file per session. The file is byte for byte
    \\                      the log, so `chock sessions verify` reads it there too.
    \\  --export-syslog <path>
    \\                      Ship each line of the log to this unix datagram socket as
    \\                      an RFC 5424 message. Usually /dev/log on Linux and
    \\                      /var/run/syslog on Darwin. A syslog message is not a copy
    \\                      of the log: use --export-dir for one that verifies.
    \\                      An org policy bundle can require a sink of either kind.
    \\                      These options add to what it requires and can remove
    \\                      none of it. A required sink that this machine cannot
    \\                      reach does not stop the session; it is said at the start
    \\                      and again at the end, and a gap that is still open when
    \\                      the session ends exits 9.
    \\
++ tty.options_text;

const max_stdin_bytes: usize = 4 * 1024 * 1024;

const shown_result_bytes: usize = 800;

const Options = struct {
    provider: ?[]const u8 = null,
    model: ?[]const u8 = null,
    project: ?[]const u8 = null,
    session: ?[]const u8 = null,
    agent_kind: []const u8 = "main",
    org_bundle: ?[]const u8 = null,
    /// Every file `--instructions` named, in the order given.
    instructions: []const []const u8 = &.{},
    max_turns: ?usize = null,
    /// Overrides `.nix.dev_shell` for one run.
    dev_shell: ?[]const u8 = null,
    /// Every rule `--policy-rule` named, in the order given.
    policy_rules: []const chock_policy.table.Rule = &.{},
    continue_newest: bool = false,
    adopt: bool = false,
    allow_dirty: bool = false,
    no_notices: bool = false,
    export_dir: ?[]const u8 = null,
    export_syslog: ?[]const u8 = null,
    parent_session: []const u8 = "",
    parent_chain: []const chock_proto.event.SpawnLink = &.{},
    scratchpad: []const u8 = "",
    max_cost: ?f64 = null,
    currency: []const u8 = "",
    message_words: []const []const u8 = &.{},
    display: ?Display = null,
    help_wanted: bool = false,
};

pub const Display = struct {
    attach: ui.Attach,
    first_message: []const u8 = "",
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    return mainWith(arena, gpa, environ, exe_path, args, null);
}

pub fn mainWithInterface(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
    attach: ui.Attach,
    first_message: []const u8,
) !u8 {
    return mainWith(arena, gpa, environ, exe_path, args, .{
        .attach = attach,
        .first_message = first_message,
    });
}

pub fn readOptions(arena: std.mem.Allocator, args: []const []const u8) !?Options {
    return parseOptions(arena, args) catch |err| switch (err) {
        error.HelpWanted => help: {
            tty.out(.plain, "{s}", .{usage_text});
            var asked = Options{};
            asked.help_wanted = true;
            break :help asked;
        },
        error.BadArguments => null,
        else => |e| return e,
    };
}

fn mainWith(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
    display: ?Display,
) !u8 {
    var options = (try readOptions(arena, args)) orelse return Exit.usage.code();
    if (options.help_wanted) return Exit.finished.code();
    options.display = display;

    if (options.display) |*wanted| {
        if (options.message_words.len != 0) {
            wanted.first_message = try std.mem.join(arena, " ", options.message_words);
        }
    }

    var env = try environ.createMap(arena);

    // `Workspace.open` spawns a bare `git`, and without `.environ` `Threaded`
    // resolves it against a compiled in `PATH` that holds no `git` on a Nix
    // machine.
    var setup_threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    const setup_io = setup_threaded.io();

    var started = start(arena, gpa, setup_io, &env, exe_path, options) catch |err| switch (err) {
        error.Reported => {
            setup_threaded.deinit();
            return Exit.usage.code();
        },
        else => |e| {
            setup_threaded.deinit();
            return e;
        },
    };
    setup_threaded.deinit();

    // `fork` carries only the calling thread, so phase 2 runs on an `Io` whose
    // allocator is `failing`: `Threaded` uses that allocator to start threads
    // and for little else, and a thread here gives a forked child that
    // deadlocks.
    var take_up: ?[]const u8 = null;
    var shipped: ShippingReport = .{};

    const outcome = phase: {
        var session_threaded = std.Io.Threaded.init(std.mem.Allocator.failing, .{ .environ = environ });
        defer session_threaded.deinit();
        break :phase runSession(gpa, session_threaded.io(), environ, &env, &started, options, &take_up, &shipped);
    };

    var teardown_threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer teardown_threaded.deinit();
    const teardown_io = teardown_threaded.io();

    const gave_away = handedOver(outcome);
    const applied = if (gave_away) Applied.nothing_to_apply else applyWork(
        gpa,
        teardown_io,
        environ,
        &env,
        &started,
        options,
    ) catch |err| blk: {
        tty.print(.err, "chock run: the session's work could not be applied: {s}\n", .{@errorName(err)});
        break :blk Applied.failed;
    };

    reportNotes(teardown_io, &started);

    reportShipping(&shipped);

    if (started.approvals) |endpoint| endpoint.close(teardown_io);

    started.storage.close(teardown_io);

    handover.disarm();
    if (started.handovers) |endpoint| endpoint.close(teardown_io);

    const session_exit: ?Exit = if (outcome) |value| value else |_| null;
    takeDownWorkspace(
        &started.workspace,
        cleanupFor(session_exit, applied),
        arena,
        teardown_io,
        &env,
        started.paths.work,
    );

    if (started.scratch_owned and !gave_away) {
        if (started.scratch_dir) |dir| chock_core.scratchpad.remove(teardown_io, dir);
    }

    if (started.dev_shell) |*shell| shell.deinit();
    if (started.device_source) |source| source.deinit();
    // Lets go here of the shared lock on the extracted tree, which stops
    // another session removing it while a tool call still binds it. This is
    // the last point at which a tool call of this session can be running.
    if (started.image) |*one| one.deinit(teardown_io);

    const result = outcome catch |err| {
        // `Busy` is a second owner and not a fault: the kernel refused the
        // second asker for the log's exclusive lock.
        if (err == error.Busy) {
            tty.print(.err, "chock run: {s}\n", .{busy_detail});
            return Exit.usage.code();
        }
        tty.print(.err, "chock run: the session failed: {s}\n", .{@errorName(err)});
        return Exit.faulted.code();
    };

    if (take_up) |id| {
        defer gpa.free(id);
        return takeUp(teardown_io, &env, started.exe_path, started.project_root, id);
    }

    return exitWithApply(result, applied, &shipped).code();
}

/// Take up another session of this project, in place of this one. A child and
/// not an `execve`: Zig 0.16 exposes no portable `execve` and this program does
/// not link libc.
fn takeUp(
    io: std.Io,
    env: *const std.process.Environ.Map,
    exe_path: []const u8,
    project_root: []const u8,
    id: []const u8,
) !u8 {
    // `--project` and not the working directory, which the child inherits from
    // this process and which may be anywhere.
    const argv = [_][]const u8{
        exe_path,
        "run",
        "--project",
        project_root,
        "--session",
        id,
        "--adopt",
    };

    var child = std.process.spawn(io, .{
        .argv = &argv,
        .environ_map = env,
    }) catch |err| {
        tty.print(
            .err,
            "chock: session {s} could not be taken up ({s}). It was not started, and this one " ++
                "has ended. `chock run --session {s} --adopt` is what this would have run.\n",
            .{ id, @errorName(err), id },
        );
        return Exit.faulted.code();
    };
    return switch (try child.wait(io)) {
        .exited => |code| code,
        else => Exit.faulted.code(),
    };
}

const Applied = enum {
    nothing_to_apply,
    uncommitted,
    landed,
    refused,
    failed,
};

const Cleanup = enum {
    remove,
    keep,
    hand_on,
};

fn cleanupFor(session_exit: ?Exit, applied: Applied) Cleanup {
    const ended = session_exit orelse return .keep;
    if (ended == .handed_over) return .hand_on;
    if (ended != .finished) return .keep;
    return switch (applied) {
        .nothing_to_apply, .landed => .remove,
        .uncommitted, .refused, .failed => .keep,
    };
}

/// A process that adopted a workspace never removes it: the checkout
/// `Workspace.close` would force away holds another owner's work.
fn releaseOnFailure(adopted: bool) Cleanup {
    return if (adopted) .keep else .remove;
}

fn handedOver(outcome: anyerror!Exit) bool {
    const ended = outcome catch return false;
    return ended == .handed_over;
}

/// `workspace` is not valid after this call returns, either way.
fn takeDownWorkspace(
    workspace: *chock_workspace.Workspace,
    cleanup: Cleanup,
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    scratch_path: []const u8,
) void {
    var close_diag: ?chock_workspace.Diagnostic = null;
    switch (cleanup) {
        .remove => workspace.close(arena, io, env, &close_diag) catch |err| {
            if (close_diag) |*fault| {
                tty.print(.err, "chock run: the workspace at {s} could not be removed: {f}\n", .{
                    scratch_path,
                    fault,
                });
            } else {
                tty.print(.err, "chock run: the workspace at {s} could not be removed: {s}\n", .{
                    scratch_path,
                    @errorName(err),
                });
            }
        },
        .keep => {
            // Named before the value is freed: `workPath` borrows from the
            // workspace, and `keep` ends it.
            reportKeptWorkspace(workspace.workPath());
            workspace.keep(arena);
        },
        .hand_on => {
            tty.detail("chock run: the workspace stays for the next owner: {s}\n", .{workspace.workPath()});
            workspace.keep(arena);
        },
    }
}

fn reportKeptWorkspace(path: []const u8) void {
    tty.print(
        .warn,
        "chock run: this session did not end cleanly, so its workspace is kept:\n" ++
            "           {s}\n" ++
            "chock run: whatever the agent wrote is still there. `chock workspace` lists every\n" ++
            "           kept workspace of this project with its size, and `chock workspace clear`\n" ++
            "           removes them.\n",
        .{path},
    );
}

fn exitWithApply(session_exit: Exit, applied: Applied, shipped: *const ShippingReport) Exit {
    if (session_exit != .finished) return session_exit;
    const landed: Exit = switch (applied) {
        .nothing_to_apply, .landed => .finished,
        .refused => .refused,
        .uncommitted, .failed => .faulted,
    };
    return exitWithAudit(landed, shipped);
}

/// A required audit sink never stops a session and never refuses to start one.
/// A sink that went down and came back leaves no gap: the log on disk is the
/// queue.
fn exitWithAudit(session_exit: Exit, report: *const ShippingReport) Exit {
    if (session_exit != .finished) return session_exit;
    return if (report.requiredGap()) .audit_gap else .finished;
}

const Started = struct {
    exe_path: []const u8,
    project_root: []const u8,
    paths: session_paths.Paths,
    session_id: []const u8,
    workspace: chock_workspace.Workspace,
    policy: *const chock_policy.table.Table,
    sandbox_config: sandbox.Config,
    dev_shell: ?chock_nix.DevShell,
    /// Owns strings `toolchain`, `sandbox_config.env` and `tool_env` borrow. A
    /// session has one of this and `dev_shell`, never both.
    image: ?chock_container.Image,
    toolchain: Toolchain,
    tool_env: *std.process.Environ.Map,
    provisioning: ?Provisioning,
    nix_build: ?NixBuild,
    nix_caps: chock_policy.nix.Resolved,
    search: chock_policy.search.Search,
    /// The key itself, read out of the credential store, and not the name the
    /// `search` block gives. Null when the block names none, or when the store
    /// holds nothing under that name yet.
    search_credential: ?[]const u8,
    backing: *chock_proto.storage.JsonLines,
    storage: chock_proto.storage.Storage,
    base_url: []const u8,
    adapter: chock_provider.Client.Adapter,
    budget: ?chock_cost.budget.Budget,
    billing: chock_cost.prices.Billing,
    subagents: chock_policy.subagents.Limits,
    apply_mode: ApplyMode,
    language_server: ?chock_core.lsp_driver.Settings,
    /// Owns the signal pipe, and `sandbox_config.device_source` borrows this
    /// pointer until phase 3.
    device_source: ?*chock_core.devices.HostSource,
    mcp_servers: ?[]const chock_core.mcp.Settings,
    plugins: ?[]const chock_core.plugin.Settings,
    prompt_project: chock_core.prompt.Project,
    prompt_sources: chock_core.prompt.Sources,
    spawn_chain: []const chock_proto.event.SpawnLink,
    session_config: chock_proto.event.SessionConfig,
    credential: chock_auth.lookup.Resolved,
    model: []const u8,
    model_alias: []const u8,
    system_prompt: []const u8,
    tool_definitions: []chock_core.tools.Definition,
    memory_dir: ?[]const u8,
    notes_at_start: usize,
    cache_dir: ?[]const u8,
    scratch_dir: ?[]const u8,
    scratch_owned: bool,
    tasks_dir: ?[]const u8,
    context_tokens: ?u64,
    uncommitted_files: usize,
    /// A pointer, because a `Waiter` holds one and `start` returns by value. Null
    /// when the socket could not be made, and a question nobody can be asked is
    /// refused.
    approvals: ?*chock_broker.socket.Endpoint,
    handovers: ?*chock_broker.handover.Endpoint,
    attempt: []const u8,
    audit_sinks: []const PlannedSink,
    redact: chock_core.redact.Policy,
    redact_values: []const []const u8,
};

const StartError = error{Reported} || std.mem.Allocator.Error;

/// An installed bundle that has expired still binds, in full: a bundle can only
/// narrow, so dropping one can only widen, and at the moment nobody can be
/// reached. `--org-bundle` is somebody handing Chock a file now, so an expired
/// one is refused there and a path that names nothing is a fault.
fn loadOrgBundle(
    arena: std.mem.Allocator,
    io: std.Io,
    data_dir: []const u8,
    options: Options,
) StartError!?*const chock_policy.org.Bundle {
    const named = options.org_bundle;

    // A subagent reads the installed bundle and never a named one. A parent
    // writes its child's command line and carries no bundle, so a child given a
    // path here would run under a wider org policy than its parent.
    if (named != null and options.parent_chain.len != 0) {
        tty.print(
            .err,
            "chock run: --org-bundle names a file for this session alone, and a subagent takes " ++
                "its org policy from the installation, the same file its parent read. Install " ++
                "the bundle instead of naming it.\n",
            .{},
        );
        return error.Reported;
    }

    const path = named orelse
        try std.fs.path.join(arena, &.{ data_dir, chock_policy.org.file_name });

    var diag: ?chock_policy.org.Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);
    const bundle = chock_policy.org.load(arena, io, path, &diag) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.NoBundleFile => {
            if (named) |asked| {
                tty.print(.err, "chock run: there is no org policy bundle at {s}.\n", .{asked});
                return error.Reported;
            }
            return null;
        },
        else => {
            if (diag) |*d| {
                tty.print(.err, "chock run: {f}\n", .{d});
            } else {
                tty.print(.err, "chock run: the org policy bundle at {s} could not be read: {t}\n", .{ path, err });
            }
            return error.Reported;
        },
    };

    const now_ms = std.Io.Timestamp.now(io, .real).toMilliseconds();

    if (named) |asked| try refuseUninstallableBundle(bundle, now_ms, asked);
    reportOrgBundle(bundle, now_ms);
    return bundle;
}

fn refuseUninstallableBundle(
    bundle: *const chock_policy.org.Bundle,
    now_ms: i64,
    path: []const u8,
) StartError!void {
    const why = chock_policy.org.refusalForInstall(bundle, now_ms) orelse return;
    tty.print(.err, "chock run: {s}\n", .{why});
    tty.print(.err, "  the bundle is {s}\n", .{path});
    return error.Reported;
}

fn reportOrgBundle(bundle: *const chock_policy.org.Bundle, now_ms: i64) void {
    if (bundle.subject.len != 0) {
        tty.print(.plain, "chock: org policy for {s}", .{bundle.subject});
        if (bundle.issuer.len != 0) tty.print(.plain, ", issued by {s}", .{bundle.issuer});
        tty.print(.plain, ", {d} rule{s}\n", .{
            bundle.rules.len,
            if (bundle.rules.len == 1) "" else "s",
        });
    }

    if (orgBudgetCeiling(bundle)) |ceiling| {
        tty.print(.plain, "chock: org policy budget ceiling {d} {s}\n", .{
            ceiling.max_cost,
            ceiling.currency,
        });
    }

    const stale_ms = bundle.expiredForMs(now_ms) orelse return;
    const days = daysIn(stale_ms);
    tty.print(
        .warn,
        "chock: this org policy bundle expired {d} day{s} ago. It still binds this session, " ++
            "because dropping it could only widen what the session may do. Ask whoever issued " ++
            "it for a current one.\n",
        .{ days, if (days == 1) "" else "s" },
    );
}

fn daysIn(span_ms: i64) i64 {
    return @divFloor(span_ms, std.time.ms_per_day);
}

/// A rule given on the command line is not in a file anybody can read back, so
/// the session says every one of them. They reach no subagent: a child reads
/// the project's file and the org bundle alone.
/// What a person gave this run, and the content of the file the policy came
/// from. Only what is there: a reader of the log sees what the session had,
/// and every field it does not carry is one nobody set.
fn sessionConfig(
    arena: std.mem.Allocator,
    options: Options,
    policy: *const chock_policy.table.Table,
    dev_shell_name: ?[]const u8,
    sandbox_config: sandbox.Config,
) std.mem.Allocator.Error!chock_proto.event.SessionConfig {
    var rules: std.ArrayList([]const u8) = .empty;
    for (options.policy_rules) |rule| {
        try rules.append(arena, try std.fmt.allocPrint(arena, "{s}={s}", .{
            rule.action orelse "*",
            @tagName(rule.decision),
        }));
    }

    return .{
        .config_hash = if (policy.hasFile())
            try std.fmt.allocPrint(arena, "{x}", .{policy.sourceHash()})
        else
            null,
        .sandbox_hash = try std.fmt.allocPrint(arena, "{x}", .{sandbox_config.shapeHash()}),
        .instructions = options.instructions,
        .policy_rules = rules.items,
        .dev_shell = dev_shell_name orelse "",
        .allow_dirty = options.allow_dirty,
    };
}

fn reportGivenRules(rules: []const chock_policy.table.Rule) void {
    for (rules) |rule| {
        tty.print(
            .warn,
            "chock run: --policy-rule answers {s} for {s}, above this project's chock.zon.\n",
            .{ @tagName(rule.decision), rule.action orelse "*" },
        );
    }
}

fn loadPolicyUnder(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    org_bundle: ?*const chock_policy.org.Bundle,
    given: []const chock_policy.table.Rule,
) StartError!*const chock_policy.table.Table {
    const org_rules: []const chock_policy.table.Rule =
        if (org_bundle) |bundle| bundle.rules else &.{};
    const layers = chock_policy.table.Table.Layers{ .given = given, .org = org_rules };

    var policy_diag: ?chock_policy.table.Diagnostic = null;
    defer if (policy_diag) |*d| d.deinit(arena);
    return chock_policy.table.Table.loadLayered(
        arena,
        io,
        project_root,
        layers,
        &policy_diag,
    ) catch |err| switch (err) {
        error.NoPolicyFile => chock_policy.table.Table.parseLayered(arena, ".{}", layers, null) catch
            return error.OutOfMemory,
        else => {
            if (policy_diag) |*d| {
                tty.print(.err, "chock run: the policy in chock.zon could not be read: {f}\n", .{d});
            } else {
                tty.print(.err, "chock run: the policy in chock.zon could not be read: {t}\n", .{err});
            }
            return error.Reported;
        },
    };
}

fn refuseProviderAndModel(
    arena: std.mem.Allocator,
    policy: *const chock_policy.table.Table,
    chain_links: []const chock_proto.event.SpawnLink,
    options: Options,
    instance_name: []const u8,
    model: []const u8,
) StartError!void {
    const rows = chock_policy.access.rowsFor(instance_name, model) catch |err| {
        tty.print(
            .err,
            "chock run: the provider {s} and the model {s} cannot be named in a policy rule: {t}. " ++
                "A provider name and a model id are short names, and neither may hold a \"*\".\n",
            .{ instance_name, model, err },
        );
        return error.Reported;
    };

    const chain = try arena.alloc([]const u8, chain_links.len + 1);
    defer arena.free(chain);
    for (chain_links, chain[0..chain_links.len]) |link, *slot| slot.* = link.agent_kind;
    chain[chain_links.len] = options.agent_kind;

    var fault: ?chock_policy.table.ChainFault = null;
    const decision = chock_policy.access.ceiling(policy, .{
        .chain = chain,
        .agent_kind = options.agent_kind,
        .model_alias = instance_name,
    }, &rows, &fault);
    if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});

    if (!chock_policy.access.refusalNeeded(decision)) return;

    tty.print(
        .err,
        "chock run: this session may not use the model {s} at the provider {s}. " ++
            "The policy answers {t} for {s} and {s}.\n",
        .{ model, instance_name, decision, rows.instance(), rows.model() },
    );
    if (chain.len > 1) {
        tty.print(
            .err,
            "  The answer is folded over the whole spawn chain, so an agent holds no model its " ++
                "parent lacks.\n",
            .{},
        );
    }
    return error.Reported;
}

fn start(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *std.process.Environ.Map,
    exe_path: []const u8,
    options: Options,
) StartError!Started {
    const project_root = try resolveProject(arena, io, options);

    const config_dir = chock_auth.paths.configDir(arena, env) catch |err| {
        tty.print(.err, "chock run: the configuration directory is unknown: {s}\n", .{@errorName(err)});
        return error.Reported;
    };
    const data_dir = chock_auth.paths.dataDir(arena, env) catch |err| {
        tty.print(.err, "chock run: the data directory is unknown: {s}\n", .{@errorName(err)});
        return error.Reported;
    };

    const org_bundle = try loadOrgBundle(arena, io, data_dir, options);

    var config_diag: ?chock_auth.config.Diagnostic = null;
    defer if (config_diag) |*d| d.deinit(arena);
    var config = chock_auth.config.load(arena, io, config_dir, &config_diag) catch |err| switch (err) {
        error.NoConfigFile => {
            tty.print(
                .err,
                "chock run: there is no configuration at {s}/{s}. Write one, for example:\n\n",
                .{ config_dir, chock_auth.config.file_name },
            );
            tty.print(
                .err,
                "  .{{\n" ++
                    "      .providers = .{{\n" ++
                    "          .{{ .name = \"local\", .kind = \"openai-compat\", " ++
                    ".base_url = \"http://127.0.0.1:5000/v1\", .context_tokens = 65536 }},\n" ++
                    "      }},\n" ++
                    "      .defaults = .{{ .provider = \"local\", .model = \"glm4.7-flash:A3B\" }},\n" ++
                    "  }}\n",
                .{},
            );
            return error.Reported;
        },
        else => {
            if (config_diag) |*d| {
                tty.print(.err, "chock run: the configuration could not be read: {f}\n", .{d});
            } else {
                tty.print(.err, "chock run: the configuration could not be read: {s}\n", .{@errorName(err)});
            }
            return error.Reported;
        },
    };

    const instance = pick: {
        if (options.provider) |name| {
            break :pick config.find(name) orelse {
                tty.print(
                    .err,
                    "chock run: the configuration names no provider called \"{s}\". It names {d}:\n",
                    .{ name, config.instances.len },
                );
                for (config.instances) |candidate| {
                    tty.print(.err, "  {s} ({s})\n", .{ candidate.name, candidate.kind.wireName() });
                }
                return error.Reported;
            };
        }
        break :pick config.defaultInstance() orelse {
            tty.print(
                .err,
                "chock run: the configuration names {d} providers and no default. " ++
                    "Name one with --provider, or set .defaults.provider in {s}/{s}.\n",
                .{ config.instances.len, config_dir, chock_auth.config.file_name },
            );
            return error.Reported;
        };
    };

    const model = options.model orelse config.default_model orelse {
        tty.print(
            .err,
            "chock run: no model was named. Give --model, or set .defaults.model in {s}/{s}.\n",
            .{ config_dir, chock_auth.config.file_name },
        );
        return error.Reported;
    };

    const driver = chock_auth.store.Driver{ .data_dir = data_dir };
    const store = chock_auth.store.Store{ .data_dir = data_dir, .secrets = driver.secrets() };
    var credential_diag: ?chock_auth.lookup.Diagnostic = null;
    defer if (credential_diag) |*d| d.deinit(arena);
    const credential = chock_auth.lookup.resolve(
        arena,
        io,
        instance,
        config_dir,
        store,
        &credential_diag,
    ) catch |err| {
        if (credential_diag) |*d| {
            tty.print(
                .err,
                "chock run: the credential for the provider {s} could not be read: {f}\n",
                .{ instance.name, d },
            );
        } else {
            tty.print(
                .err,
                "chock run: the credential for the provider {s} could not be read: {s}\n",
                .{ instance.name, @errorName(err) },
            );
        }
        return error.Reported;
    };

    if (chock_auth.lookup.credentialIsMissing(instance, credential.source)) {
        tty.print(
            .err,
            "chock run: the provider {s} has no credential. It talks to {s}, which refuses a " ++
                "request that carries none, so this session would fail on its first turn.\n",
            .{ instance.name, instance.base_url },
        );
        tty.print(
            .err,
            "  Run: chock login --provider {s} --name {s}\n",
            .{ instance.kind.wireName(), instance.name },
        );
        tty.print(
            .err,
            "  Or give that provider .token_file in {s}/{s}, which is how sops-nix and agenix " ++
                "work. See docs/operate/credentials.md.\n",
            .{ config_dir, chock_auth.config.file_name },
        );
        return error.Reported;
    }

    // Before the redaction, because the search key is one of the values that
    // must never reach the log.
    const search = try resolveSearch(arena, io, config_dir, org_bundle);
    const search_credential = try loadSearchCredential(arena, io, store, search);

    const redaction = try redactionFor(
        arena,
        instance.name,
        credential.token,
        config.instances,
        search_credential,
    );

    // Copied into the arena: `chock_proto.log.Log` borrows the session string
    // and stamps it onto every envelope for as long as the log is open.
    const stack_id = try chooseSessionId(arena, io, env, project_root, options);
    const id = try arena.dupe(u8, &stack_id);

    const paths = session_paths.pathsFor(arena, env, project_root, id) catch |err| {
        tty.print(.err, "chock run: the session path could not be built: {s}\n", .{@errorName(err)});
        return error.Reported;
    };

    if (options.adopt) try refuseAdoptWithNothingToAdopt(gpa, io, paths.log, id);

    session_paths.create(io, paths) catch return error.Reported;

    const resuming = options.adopt or options.continue_newest or options.session != null;
    const taken = if (resuming) takenOver(gpa, io, arena, paths.log, paths.work) else null;

    // Before the workspace, because the `workspace` block's binds are decided
    // against this table and the mount list is built from that decision.
    const policy = try loadPolicyUnder(arena, io, project_root, org_bundle, options.policy_rules);
    reportGivenRules(options.policy_rules);

    const declared_binds = try workspaceBinds(
        arena,
        io,
        policy,
        spawnChain(options),
        options.agent_kind,
        model,
        project_root,
    );

    // Fresh on every invocation, and never the session identifier: a
    // continued session would otherwise ask `git worktree add` for a path
    // the previous run already used.
    const attempt = if (taken) |one| one.attempt else session_paths.newId(io);
    // The arena, not the general purpose allocator: `close` has to be given
    // the same allocator `open` was.
    var open_diag: ?chock_workspace.Diagnostic = null;
    var workspace = if (taken) |one| chock_workspace.Workspace.adopt(
        arena,
        io,
        env,
        project_root,
        paths.work,
        &attempt,
        one.base_commit,
        &open_diag,
    ) catch |err| {
        if (open_diag) |*fault| {
            tty.print(
                .err,
                "chock run: the workspace of session {s} could not be taken over: {f}\n",
                .{ id, fault },
            );
        } else {
            tty.print(
                .err,
                "chock run: the workspace of session {s} could not be taken over: {s}\n",
                .{ id, @errorName(err) },
            );
        }
        tty.print(
            .err,
            "chock run: that session was handed over and left its work at {s}/{s}. It is still " ++
                "there. `chock workspace` lists it and removes it.\n",
            .{ paths.work, &attempt },
        );
        return error.Reported;
    } else chock_workspace.Workspace.openAndDenied(
        arena,
        io,
        env,
        project_root,
        paths.work,
        &attempt,
        if (org_bundle) |bundle| bundle.deny_read else &.{},
        &open_diag,
    ) catch |err| {
        if (open_diag) |*fault| {
            tty.print(
                .err,
                "chock run: the workspace for {s} could not be built: {f}\n",
                .{ project_root, fault },
            );
        } else {
            tty.print(
                .err,
                "chock run: the workspace for {s} could not be built: {s}\n",
                .{ project_root, @errorName(err) },
            );
        }
        switch (err) {
            error.ScratchOnAnotherVolume => tty.print(
                .err,
                "chock run: {s} and the scratch directory {s} are on different volumes, " ++
                    "and a clone cannot cross one. Give Chock a scratch directory on the " ++
                    "project's own volume.\n",
                .{ project_root, paths.work },
            ),
            error.ScratchAlreadyExists => tty.print(
                .err,
                "chock run: the clone destination under {s} already exists, usually from a " ++
                    "session that ended abnormally. Remove it and try again.\n",
                .{paths.work},
            ),
            error.NoOverlayFilesystem => tty.print(
                .err,
                "chock run: the volume that holds {s} has no copy on write clone, so a " ++
                    "workspace cannot be built on it.\n",
                .{project_root},
            ),
            error.ChockZonNotValid, error.DenyBlockNotValid, error.ChockZonTooLarge => tty.print(
                .err,
                "chock run: that file is {s}/chock.zon. docs/configure/configuration.md holds a complete " ++
                    "one, and docs/configure/policy.md holds the policy block.\n",
                .{project_root},
            ),
            else => {},
        }
        return error.Reported;
    };
    errdefer switch (releaseOnFailure(taken != null)) {
        .keep => workspace.keep(arena),
        .remove => workspace.close(arena, io, env, null) catch {},
        .hand_on => unreachable,
    };

    try attachBinds(arena, io, &workspace, declared_binds, taken == null);

    var sandbox_config = workspace.sandboxConfig(arena, paths.root) catch |err| {
        tty.print(.err, "chock run: the sandbox could not be described: {s}\n", .{@errorName(err)});
        return error.Reported;
    };

    const backing = try arena.create(chock_proto.storage.JsonLines);
    backing.* = .{ .log = chock_proto.log.Log.open(io, paths.log, id) catch |err| {
        tty.print(.err, "chock run: the session log {s} could not be opened: {s}\n", .{ paths.log, @errorName(err) });
        return error.Reported;
    } };
    const storage = backing.storage();

    tty.print(.plain, "chock: session {s}, model {s} via {s}\n", .{ id, model, instance.name });
    tty.detail("chock: log {s}\n", .{paths.log});
    tty.detail("chock: provider {s} ({s}), {s}\n", .{
        instance.name,
        instance.base_url,
        credential.source.describe(),
    });

    // Before the two control sockets, because this is what proves this process
    // owns the session. `Endpoint.open` removes whatever file is at the path, so
    // a second run against a live session unlinked that session's approval and
    // handover sockets and left it listening on an inode nothing could reach.
    recordWorkspace(gpa, io, storage, &workspace, &attempt) catch |err| {
        if (err == error.Busy) {
            tty.print(.err, "chock run: {s}\n", .{busy_detail});
        } else {
            tty.print(
                .err,
                "chock run: the workspace could not be written to the log: {s}. Without that, a " ++
                    "handover of this session would lose the work in it.\n",
                .{@errorName(err)},
            );
        }
        return error.Reported;
    };

    const approvals = approvalEndpoint(arena, io, paths.dir, id);

    const handovers = handoverEndpoint(arena, io, paths.dir, id);

    const dev_shell_dir = devShellDirFor(arena, io, env, project_root);

    // Before the dev shell, because the `nix` block names the attribute it
    // reads. `--dev-shell` wins over the file for this one run.
    const nix_caps = try resolveNixCaps(arena, io, project_root, config_dir, org_bundle);
    const dev_shell_name = options.dev_shell orelse nix_caps.dev_shell;

    const flake_inputs = fetchFlakeInputs(
        arena,
        io,
        env,
        policy,
        project_root,
        spawnChain(options),
        options.agent_kind,
        model,
    );

    var image = try loadImage(gpa, arena, io, env, project_root);
    errdefer if (image) |*one| one.deinit(io);

    const dev_shell = if (image != null)
        null
    else
        try loadDevShell(gpa, io, env, project_root, dev_shell_dir, dev_shell_name);

    const tool_env = if (image) |*one|
        try imageToolEnvironment(arena, one)
    else
        try toolEnvironment(arena, env, dev_shell);

    if (image) |*one| {
        sandbox_config.env = try imageSandboxEnvironment(arena, sandbox_config.env, one);
    } else if (dev_shell) |shell| {
        sandbox_config.env = try sandboxEnvironment(arena, sandbox_config.env, shell);
    }

    const toolchain = try toolchainFor(
        arena,
        io,
        project_root,
        dev_shell,
        if (image) |*one| one else null,
        sandbox_config.mounts,
    );

    // A workspace this process took over imports nothing. `--allow-dirty` copies
    // every path `git status` names over the same path in the workspace, and on
    // an adopted one those may be files the last owner's agent wrote.
    if (taken != null and options.allow_dirty) {
        tty.print(
            .err,
            "chock run: session {s} carries on in the workspace its last owner left, and " ++
                "--allow-dirty copies your uncommitted files over the files in it. Those are the " ++
                "agent's own edits. Run this without --allow-dirty.\n",
            .{id},
        );
        return error.Reported;
    }
    const uncommitted_files = if (taken != null)
        0
    else
        try handleUncommitted(gpa, io, env, &workspace, options);

    const write_execute = try hardeningDecision(
        arena,
        policy,
        spawnChain(options),
        options.agent_kind,
        model,
    );
    sandbox_config.seccomp_options.strict_wx = write_execute.rule == .strict;

    sandbox_config.network = if (policy.wantsRouter()) .filtered else .none;

    if (try resolveLimits(arena, io, project_root, config_dir, org_bundle)) |resolved| {
        applyLimits(&sandbox_config, resolved);
        // The program these numbers bound cannot read them: `/sys/fs/cgroup` is
        // hidden inside the sandbox and `/proc/meminfo` reports the whole
        // machine.
        if (resolved.processes_from_org) {
            tty.print(
                .warn,
                "chock run: the org policy bundle holds this session to {d} processes.\n",
                .{resolved.processes},
            );
        }
        if (resolved.memory_from_org) {
            tty.print(
                .warn,
                "chock run: the org policy bundle holds this session to {d} MiB of memory.\n",
                .{resolved.memory_bytes >> 20},
            );
        }
    }

    try recordSandbox(gpa, io, storage, &attempt, write_execute);

    var devices_diag: ?chock_core.devices.Diagnostic = null;
    defer if (devices_diag) |*d| d.deinit(arena);
    const declared_devices = chock_core.devices.load(arena, io, project_root, &devices_diag) catch |err| {
        if (devices_diag) |*d| {
            tty.print(.err, "chock run: the devices block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the devices block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };
    const device_wiring = try devicesFor(
        arena,
        gpa,
        io,
        policy,
        spawnChain(options),
        options.agent_kind,
        model,
        declared_devices,
    );
    try recordDevices(gpa, io, storage, &attempt, device_wiring.seam);
    const device_source: ?*chock_core.devices.HostSource = device_wiring.host;
    if (device_wiring.host) |host| {
        sandbox_config.device_tree = device_wiring.device_tree;
        sandbox_config.device_source = host.deviceSource();
    }

    const apply_mode = try applyModeFor(
        arena,
        io,
        project_root,
        policy,
        spawnChain(options),
        options.agent_kind,
        model,
    );

    try refuseProviderAndModel(arena, policy, spawnChain(options), options, instance.name, model);

    var budget_diag: ?chock_cost.budget.Diagnostic = null;
    defer if (budget_diag) |*d| d.deinit(arena);
    const from_file = chock_cost.budget.load(arena, io, project_root, &budget_diag) catch |err| {
        if (budget_diag) |*d| {
            tty.print(.err, "chock run: the budget in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the budget in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };
    const budget = try budgetUnderOrg(arena, from_file, options, org_bundle);
    const billing = chock_cost.prices.billingFor(instance.base_url);
    warnUnmeasurableBudget(budget, billing, instance.name, model);

    var subagents_diag: ?chock_policy.subagents.Diagnostic = null;
    defer if (subagents_diag) |*d| d.deinit(arena);
    const limits_from_file = chock_policy.subagents.load(arena, io, project_root, &subagents_diag) catch |err| {
        if (subagents_diag) |*d| {
            tty.print(.err, "chock run: the subagents block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the subagents block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };
    const subagent_limits = subagentsUnderOrg(limits_from_file, org_bundle);

    var language_server_diag: ?chock_core.lsp_driver.Diagnostic = null;
    defer if (language_server_diag) |*d| d.deinit(arena);
    const language_server = chock_core.lsp_driver.load(
        arena,
        io,
        project_root,
        &language_server_diag,
    ) catch |err| {
        if (language_server_diag) |*d| {
            tty.print(.err, "chock run: the language_servers block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the language_servers block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };

    var mcp_diag: ?chock_core.mcp.Diagnostic = null;
    defer if (mcp_diag) |*d| d.deinit(arena);
    const mcp_servers = chock_core.mcp.load(arena, io, project_root, &mcp_diag) catch |err| {
        if (mcp_diag) |*d| {
            tty.print(.err, "chock run: the mcp_servers block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the mcp_servers block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };

    var plugins_diag: ?chock_core.plugin.Diagnostic = null;
    defer if (plugins_diag) |*d| d.deinit(arena);
    const plugins = chock_core.plugin.load(arena, io, project_root, &plugins_diag) catch |err| {
        if (plugins_diag) |*d| {
            tty.print(.err, "chock run: the plugins block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the plugins block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };

    const adapter: chock_provider.Client.Adapter = switch (instance.kind) {
        .anthropic => .anthropic,
        .aiand, .openai_compat => .openai_compatible,
    };

    const memory_dir = session_paths.memoryDir(arena, env, project_root) catch |err| {
        tty.print(.err, "chock run: the knowledgebase directory is unknown: {s}\n", .{@errorName(err)});
        return error.Reported;
    };
    const memory_ready = if (session_paths.createMemoryDir(io, memory_dir)) true else |_| ready: {
        tty.print(
            .warn,
            "chock run: the knowledgebase directory {s} could not be made, so this session " ++
                "keeps no notes.\n",
            .{memory_dir},
        );
        break :ready false;
    };

    const cache_dir = resolvedForSandbox(arena, io, prepareCache(arena, gpa, io, env, project_root));

    const scratch_dir = resolvedForSandbox(arena, io, prepareScratchpad(arena, gpa, io, env, id, options));
    const tasks_dir: ?[]const u8 = if (scratch_dir) |dir|
        std.fs.path.join(arena, &.{ dir, chock_core.tasks.host_leaf }) catch return error.OutOfMemory
    else
        null;

    const chain = spawnChain(options);
    const provisioning = try provisioningFor(
        arena,
        io,
        env,
        policy,
        options,
        chain,
        model,
        dev_shell_dir,
    );

    const nix_build = nixBuildFor(
        arena,
        io,
        env,
        dev_shell_dir,
        workspace.workPath(),
        nix_caps,
        flake_inputs,
    );

    const support = chock_core.tools.Support{
        .adapter = adapter,
        .provider = .{ .images = instance.capabilities.images },
        .memory = memory_ready,
        .provisioning = provisioning != null,
        .nix_build = nix_build != null,
        // An evaluation runs in this process, so it needs no `nix` binary,
        // no daemon and no store.
        .nix_eval = true,
        .role = agentRole(options),
    };

    const project_named = try projectNamedInstructions(arena, io, project_root);

    var given_diag: chock_core.instructions.GivenDiagnostic = .{};
    var project_named_diag: chock_core.instructions.ProjectNamedDiagnostic = .{};
    const loaded_instructions = chock_core.instructions.load(
        arena,
        io,
        config_dir,
        project_root,
        options.instructions,
        &given_diag,
        project_named,
        &project_named_diag,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.GivenFileUnreadable => {
            tty.print(
                .err,
                "chock run: the instructions file {s} could not be read. A file named with " ++
                    "--instructions is one this session was asked for, so it does not start " ++
                    "without it.\n",
                .{given_diag.path},
            );
            return error.Reported;
        },
        error.ProjectNamedFileUnreadable => {
            tty.print(
                .err,
                "chock run: the instruction {s} named in chock.zon could not be read. A file " ++
                    "the project's own instructions block names is one this session was asked " ++
                    "for, so it does not start without it.\n",
                .{project_named_diag.path},
            );
            return error.Reported;
        },
    };
    reportInstructions(loaded_instructions);

    const notes = chock_core.memory.list(arena, io, memory_dir) catch return error.OutOfMemory;
    const note_index = chock_core.memory.indexOf(arena, notes) catch return error.OutOfMemory;
    if (notes.len != 0) {
        tty.detail("chock: {d} notes from earlier sessions ({s})\n", .{ notes.len, memory_dir });
    }

    const tool_definitions = chock_core.tools.Registry.definitions(arena, support) catch return error.OutOfMemory;
    const prompt_project = projectKind(io, project_root);
    const prompt_sources = chock_core.prompt.Sources{
        .instructions = loaded_instructions,
        .guidance = chock_core.guidance.indexEntries(arena) catch return error.OutOfMemory,
        .memory = note_index,
    };
    const system_prompt = chock_core.prompt.build(
        arena,
        prompt_project,
        tool_definitions,
        prompt_sources,
    ) catch return error.OutOfMemory;

    // An adoption appends nothing and reads no standard input: a read would
    // block a daemon's child for ever on a pipe nothing writes to. A display
    // appends none either, and asks for every message it sends.
    if (!options.adopt and options.display == null) {
        const message_text = try readMessage(arena, io, options);
        if (message_text.len == 0) {
            tty.print(.err, "chock run: the message is empty, so there is nothing to ask.\n", .{});
            return error.Reported;
        }
        appendUserMessage(gpa, io, storage, message_text) catch |err| {
            tty.print(.err, "chock run: the message could not be written to the log: {s}\n", .{@errorName(err)});
            return error.Reported;
        };
    }

    return .{
        .exe_path = exe_path,
        .project_root = project_root,
        .paths = paths,
        .session_id = id,
        .workspace = workspace,
        .policy = policy,
        .sandbox_config = sandbox_config,
        .dev_shell = dev_shell,
        .image = image,
        .toolchain = toolchain,
        .tool_env = tool_env,
        .provisioning = provisioning,
        .nix_build = nix_build,
        .nix_caps = nix_caps,
        .search = search,
        .search_credential = search_credential,
        .backing = backing,
        .storage = storage,
        .base_url = instance.base_url,
        .adapter = adapter,
        .credential = credential,
        .budget = budget,
        .billing = billing,
        .subagents = subagent_limits,
        .apply_mode = apply_mode,
        .language_server = language_server,
        .device_source = device_source,
        .mcp_servers = mcp_servers,
        .plugins = plugins,
        .prompt_project = prompt_project,
        .prompt_sources = prompt_sources,
        .spawn_chain = chain,
        .session_config = try sessionConfig(arena, options, policy, dev_shell_name, sandbox_config),
        .model = model,
        .model_alias = instance.name,
        .system_prompt = system_prompt,
        .tool_definitions = tool_definitions,
        .memory_dir = if (memory_ready) memory_dir else null,
        .notes_at_start = notes.len,
        .cache_dir = cache_dir,
        .scratch_dir = scratch_dir,
        .scratch_owned = options.scratchpad.len == 0,
        .tasks_dir = tasks_dir,
        .context_tokens = instance.context_tokens,
        .uncommitted_files = uncommitted_files,
        .approvals = approvals,
        .handovers = handovers,
        .attempt = try arena.dupe(u8, &attempt),
        .audit_sinks = try auditSinks(arena, io, options, org_bundle, id),
        .redact = redaction,
        .redact_values = try brokerRedaction(arena, redaction),
    };
}

/// What this session keeps out of its own log and out of a provider request. A
/// credential shorter than `chock_core.redact.min_secret_bytes` is skipped and
/// said out loud by name, because a short value appears inside ordinary words,
/// hashes and base64.
fn redactionFor(
    arena: std.mem.Allocator,
    instance_name: []const u8,
    token: []const u8,
    instances: []const chock_auth.config.Instance,
    search_key: ?[]const u8,
) std.mem.Allocator.Error!chock_core.redact.Policy {
    const Named = struct { name: []const u8, value: []const u8 };

    var named: std.ArrayList(Named) = .empty;
    if (token.len != 0) try named.append(arena, .{ .name = instance_name, .value = token });

    // A search key reaches no provider, and it still goes in the log the moment
    // a request that carries it is written down.
    if (search_key) |key_value| {
        if (key_value.len != 0) try named.append(arena, .{ .name = "the search engine", .value = key_value });
    }

    for (instances) |one| {
        const inline_token = switch (one.credential) {
            .token => |value| value,
            .token_file, .absent => continue,
        };
        if (inline_token.len == 0) continue;
        var already = false;
        for (named.items) |seen| {
            if (std.mem.eql(u8, seen.value, inline_token)) already = true;
        }
        if (already) continue;
        try named.append(arena, .{ .name = one.name, .value = inline_token });
    }

    // One slot more than there are credentials, and the last one is empty. It is
    // where a git password goes while an approved push runs, and an empty value
    // is inert.
    const secrets = try arena.alloc(chock_core.redact.Secret, named.items.len + 1);
    for (named.items, secrets[0..named.items.len]) |one, *slot| {
        slot.* = .{ .value = one.value, .source = .credential };
    }
    secrets[named.items.len] = .{ .value = "", .source = .credential };

    for (named.items) |one| {
        if (one.value.len >= chock_core.redact.min_secret_bytes) continue;
        tty.print(
            .warn,
            "chock run: the credential for {s} is shorter than {d} bytes. It is not kept out of " ++
                "this session's log, and it is not kept out of what this session sends to the " ++
                "provider. A value that short appears inside ordinary words, so matching it would " ++
                "replace half of every request.\n",
            .{ one.name, chock_core.redact.min_secret_bytes },
        );
    }

    return .{ .secrets = secrets };
}

/// `chock-broker` imports no `chock-core`, so a `chock_core.redact.Policy`
/// cannot travel there. The values can, and they travel with no name attached.
fn brokerRedaction(
    arena: std.mem.Allocator,
    policy: chock_core.redact.Policy,
) std.mem.Allocator.Error![]const []const u8 {
    var values: std.ArrayList([]const u8) = .empty;
    for (policy.secrets) |secret| {
        if (secret.value.len < chock_core.redact.min_secret_bytes) continue;
        try values.append(arena, secret.value);
    }
    return values.toOwnedSlice(arena);
}

const PlannedSink = struct {
    kind: chock_policy.org.RequiredSink.Kind,
    path: []const u8,
    required: bool = false,
};

/// The union of `--export-dir`, `--export-syslog` and the org policy bundle: a
/// project may add a sink and cannot drop one the installation named. A sink
/// named twice is opened once, and the required entry is the one kept.
fn auditSinks(
    arena: std.mem.Allocator,
    io: std.Io,
    options: Options,
    org_bundle: ?*const chock_policy.org.Bundle,
    session_id: []const u8,
) std.mem.Allocator.Error![]const PlannedSink {
    var planned: std.ArrayList(PlannedSink) = .empty;

    if (org_bundle) |bundle| for (bundle.sinks) |one| {
        try addPlannedSink(arena, &planned, .{
            .kind = one.kind,
            .path = switch (one.kind) {
                .directory => try dropPathIn(arena, io, one.path, session_id),
                .syslog => one.path,
            },
            .required = true,
        });
    };

    if (options.export_dir) |dir| try addPlannedSink(arena, &planned, .{
        .kind = .directory,
        .path = try dropPathIn(arena, io, dir, session_id),
    });
    if (options.export_syslog) |path| try addPlannedSink(arena, &planned, .{
        .kind = .syslog,
        .path = path,
    });

    return planned.toOwnedSlice(arena);
}

fn addPlannedSink(
    arena: std.mem.Allocator,
    planned: *std.ArrayList(PlannedSink),
    one: PlannedSink,
) std.mem.Allocator.Error!void {
    for (planned.items) |held| {
        if (held.kind == one.kind and std.mem.eql(u8, held.path, one.path)) return;
    }
    try planned.append(arena, one);
}

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

fn dropPathIn(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    session_id: []const u8,
) std.mem.Allocator.Error![]const u8 {
    // Not `createDirPath`, which can loop for ever: it answers a `mkdir` of
    // `ENOENT` by walking back to a component it can make and forward again, so
    // a component whose parent exists and still cannot be made sends it between
    // the same two names without end. A path under `/proc` is that shape.
    makeDirAll(io, dir) catch {};
    return try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ dir, session_id });
}

/// The workspace a session that handed over left behind, or null. Only one opened
/// before the ending that handed it over counts: a fold never clears
/// `end_reason`, so a session that handed over once reads as `handed_over` for
/// ever, and adopting that checkout lets the live owner's teardown remove it.
fn takenOver(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    log_path: [:0]const u8,
    work_path: []const u8,
) ?struct { attempt: [session_paths.id_length]u8, base_commit: []const u8 } {
    _ = std.Io.Dir.cwd().statFile(io, log_path, .{}) catch return null;
    const log = chock_proto.log.Log.open(io, log_path, "") catch return null;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var replay = store.replay(gpa, io, 0) catch return null;
    defer replay.deinit();

    var handed_over = false;
    var ended_at: u64 = 0;
    var opened_at: ?u64 = null;
    var attempt: [session_paths.id_length]u8 = undefined;
    // A git object identifier is 40 hexadecimal characters for SHA-1 and 64 for
    // SHA-256.
    var base_buffer: [128]u8 = undefined;
    var base_len: usize = 0;

    while (replay.next(io) catch null) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .session_end => |end| {
                handed_over = end.reason == .handed_over;
                ended_at = parsed.value.id;
            },
            .workspace_open => |opened| {
                // Copied now, because the replay owns these bytes only until
                // the next line is read.
                if (opened.kind != .worktree) {
                    opened_at = null;
                    continue;
                }
                if (opened.attempt.len != session_paths.id_length) continue;
                if (!session_paths.isValidId(opened.attempt)) continue;
                if (opened.base_commit.len > base_buffer.len) continue;
                @memcpy(&attempt, opened.attempt);
                @memcpy(base_buffer[0..opened.base_commit.len], opened.base_commit);
                base_len = opened.base_commit.len;
                opened_at = parsed.value.id;
            },
            else => {},
        }
    }

    if (!handed_over) return null;
    const opened = opened_at orelse return null;
    if (opened > ended_at) return null;

    const path = std.fs.path.join(arena, &.{ work_path, &attempt }) catch return null;
    var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return null;
    dir.close(io);

    const base_commit = arena.dupe(u8, base_buffer[0..base_len]) catch return null;
    return .{ .attempt = attempt, .base_commit = base_commit };
}

fn recordWorkspace(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    workspace: *const chock_workspace.Workspace,
    attempt: []const u8,
) !void {
    var locked = try storage.lock(io);
    defer locked.unlock(io) catch {};
    _ = try locked.append(gpa, io, .{
        .workspace_open = .{
            .kind = switch (workspace.kind) {
                .worktree => .worktree,
                .overlay => .overlay,
            },
            .attempt = attempt,
            .path = workspace.workPath(),
            .base_commit = switch (workspace.kind) {
                .worktree => |wt| wt.base_commit,
                .overlay => "",
            },
        },
    }, std.Io.Timestamp.now(io, .real).toMilliseconds());
}

fn recordSandbox(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    attempt: []const u8,
    hardening: Hardening,
) StartError!void {
    var locked = storage.lock(io) catch |err| return reportSandboxRecord(err);
    defer locked.unlock(io) catch {};
    _ = locked.append(gpa, io, .{
        .sandbox_open = .{
            .attempt = attempt,
            .write_execute = switch (hardening.rule) {
                .strict => .strict,
                .relaxed => .relaxed,
            },
            .decision = @tagName(hardening.decision),
        },
    }, std.Io.Timestamp.now(io, .real).toMilliseconds()) catch |err| return reportSandboxRecord(err);
}

fn reportSandboxRecord(err: anyerror) StartError {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    if (err == error.Busy) {
        tty.print(.err, "chock run: {s}\n", .{busy_detail});
        return error.Reported;
    }
    tty.print(
        .err,
        "chock run: the sandbox this run built could not be written to the log: {s}. A session " ++
            "that cannot say which layers it ran with is one nobody can audit afterwards.\n",
        .{@errorName(err)},
    );
    return error.Reported;
}

/// `enforced` reads `chock_sandbox.expresses.device_passthrough` and not only
/// `decision`, because a build that applies neither `Config.device_tree` nor
/// `Config.device_source` grants nothing whatever policy answers.
fn recordDevices(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    attempt: []const u8,
    seam: ?*const DevicePolicySeam,
) StartError!void {
    const table = seam orelse return;
    if (table.declared.len == 0) return;

    var locked = storage.lock(io) catch |err| return reportDevicesRecord(err);
    defer locked.unlock(io) catch {};
    for (table.declared) |one| {
        const decision = table.decisionFor(one.action);
        _ = locked.append(gpa, io, .{
            .device_exposed = .{
                .attempt = attempt,
                .action = one.action,
                .decision = @tagName(decision),
                .enforced = decision == .allow and sandbox.expresses.device_passthrough,
            },
        }, std.Io.Timestamp.now(io, .real).toMilliseconds()) catch |err| return reportDevicesRecord(err);

        if (decision != .allow) tty.print(
            .warn,
            "chock: {s} is not exposed to this session, because this project's policy answers " ++
                "{t} for it. Write a rule under .policy.rules in chock.zon that answers allow for " ++
                "{s} to expose it.\n",
            .{ one.action, decision, one.action },
        );
    }
}

fn reportDevicesRecord(err: anyerror) StartError {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    if (err == error.Busy) {
        tty.print(.err, "chock run: {s}\n", .{busy_detail});
        return error.Reported;
    }
    tty.print(
        .err,
        "chock run: the devices this run declared could not be written to the log: {s}. A " ++
            "session that cannot say what it exposed is one nobody can audit afterwards.\n",
        .{@errorName(err)},
    );
    return error.Reported;
}

fn handoverEndpoint(
    arena: std.mem.Allocator,
    io: std.Io,
    session_dir: []const u8,
    id: []const u8,
) ?*chock_broker.handover.Endpoint {
    const paths = chock_broker.handover.pathsFor(arena, session_dir, id) catch return null;
    const endpoint = arena.create(chock_broker.handover.Endpoint) catch return null;
    var socket_diag: ?chock_broker.Diagnostic = null;
    endpoint.* = chock_broker.handover.Endpoint.open(io, paths, &socket_diag) catch |err| {
        if (socket_diag) |*fault| {
            tty.print(
                .warn,
                "chock run: this session has no handover socket ({f}), so `chock detach` cannot " ++
                    "take it while it runs. Stop it first.\n",
                .{fault},
            );
        } else {
            tty.print(
                .warn,
                "chock run: this session has no handover socket ({s}), so `chock detach` cannot " ++
                    "take it while it runs. Stop it first.\n",
                .{@errorName(err)},
            );
        }
        return null;
    };
    tty.detail("chock: handover {s}\n", .{paths.socket});
    return endpoint;
}

fn approvalEndpoint(
    arena: std.mem.Allocator,
    io: std.Io,
    session_dir: []const u8,
    id: []const u8,
) ?*chock_broker.socket.Endpoint {
    const paths = chock_broker.socket.pathsFor(arena, session_dir, id) catch return null;
    const endpoint = arena.create(chock_broker.socket.Endpoint) catch return null;
    var socket_diag: ?chock_broker.Diagnostic = null;
    endpoint.* = chock_broker.socket.Endpoint.open(io, paths, &socket_diag) catch |err| {
        if (socket_diag) |*fault| {
            tty.print(
                .warn,
                "chock run: this session has no approval socket ({f}), so only a person at this " ++
                    "terminal can answer a question it asks.\n",
                .{fault},
            );
        } else {
            tty.print(
                .warn,
                "chock run: this session has no approval socket ({s}), so only a person at this " ++
                    "terminal can answer a question it asks.\n",
                .{@errorName(err)},
            );
        }
        return null;
    };
    tty.detail("chock: approvals {s}\n", .{paths.socket});
    return endpoint;
}

fn orgBudgetCeiling(
    org_bundle: ?*const chock_policy.org.Bundle,
) ?chock_cost.budget.Budget {
    const bundle = org_bundle orelse return null;
    const ceiling = bundle.budget orelse return null;
    return .{
        .max_cost = ceiling.max_cost,
        .currency = if (ceiling.currency.len != 0)
            ceiling.currency
        else
            chock_cost.budget.default_currency,
    };
}

fn subagentsUnderOrg(
    from_file: chock_policy.subagents.Limits,
    org_bundle: ?*const chock_policy.org.Bundle,
) chock_policy.subagents.Limits {
    const bundle = org_bundle orelse return from_file;
    return chock_policy.subagents.underCeiling(from_file, bundle.subagents);
}

fn resolveLimits(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    config_dir: []const u8,
    org_bundle: ?*const chock_policy.org.Bundle,
) StartError!?chock_policy.limits.Resolved {
    var diag: ?chock_policy.limits.Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);

    const project = chock_policy.limits.load(arena, io, project_root, &diag) catch |err|
        return reportLimits(err, &diag);
    const operator = chock_policy.limits.loadOperator(arena, io, config_dir, &diag) catch |err|
        return reportLimits(err, &diag);

    const machine = chock_policy.limits.Machine.read() catch {
        tty.print(
            .warn,
            "chock run: this machine's cpu count and memory could not be read, so the sandbox " ++
                "keeps the built in limits rather than limits sized to it.\n",
            .{},
        );
        return null;
    };

    const ceiling = if (org_bundle) |bundle| bundle.limits else null;
    return chock_policy.limits.foldLayers(project, operator, ceiling, machine);
}

/// Assigned, and not folded through `rlimits.Limits.narrow`: that ratchet is
/// for a caller which may only ask for less, and a large machine has to reach
/// above `rlimits.default_processes`.
fn applyLimits(config: *sandbox.Config, resolved: chock_policy.limits.Resolved) void {
    config.limits.processes = resolved.processes;
    config.limits.memory_bytes = resolved.memory_bytes;
}

fn resolveNixCaps(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    config_dir: []const u8,
    org_bundle: ?*const chock_policy.org.Bundle,
) StartError!chock_policy.nix.Resolved {
    var diag: ?chock_policy.nix.Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);

    const project = chock_policy.nix.load(arena, io, project_root, &diag) catch |err|
        return reportNixCaps(err, &diag);
    const operator = chock_policy.nix.loadOperator(arena, io, config_dir, &diag) catch |err|
        return reportNixCaps(err, &diag);

    const ceiling = if (org_bundle) |bundle| bundle.nix else null;
    return chock_policy.nix.foldLayers(project, operator, ceiling);
}

fn applyNixCaps(driver: *chock_nix.backend.Driver, resolved: chock_policy.nix.Resolved) void {
    driver.max_object_bytes = std.math.cast(usize, resolved.max_object_bytes) orelse
        std.math.maxInt(usize);
}

fn reportNixCaps(err: anyerror, diag: *?chock_policy.nix.Diagnostic) StartError {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    if (diag.*) |*d| {
        tty.print(.err, "chock run: the nix block could not be read: {f}\n", .{d});
    } else {
        tty.print(.err, "chock run: the nix block could not be read: {t}\n", .{err});
    }
    return error.Reported;
}

fn reportLimits(err: anyerror, diag: *?chock_policy.limits.Diagnostic) StartError {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    if (diag.*) |*d| {
        tty.print(.err, "chock run: the limits block could not be read: {f}\n", .{d});
    } else {
        tty.print(.err, "chock run: the limits block could not be read: {t}\n", .{err});
    }
    return error.Reported;
}

/// The key of the configured search engine, read out of the credential store.
///
/// **A named credential the store has nothing under is a warning and not a
/// refusal.** A session that never searches must still start, and the tool
/// itself refuses the call with the command that puts the key there. Ending the
/// session instead would make one unconfigured engine cost every other thing the
/// agent was going to do.
fn loadSearchCredential(
    arena: std.mem.Allocator,
    io: std.Io,
    store: chock_auth.store.Store,
    search: chock_policy.search.Search,
) StartError!?[]const u8 {
    const name = search.credential orelse return null;

    var diag: ?chock_auth.store.Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);

    const held = chock_auth.search.load(arena, io, store.secrets, name, &diag) catch |err| {
        if (diag) |*d| {
            tty.print(.err, "chock run: the search key could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the search key could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };
    if (held == null) {
        tty.print(
            .warn,
            "chock run: the search block names the credential \"{s}\" and the credential store " ++
                "holds nothing under it. A search will be refused until you run:\n" ++
                "  chock login --search {s}\n",
            .{ name, name },
        );
    }
    return held;
}

/// There is no project layer for `search`: it names the operator's own
/// infrastructure, the same way a model provider does. An org bundle is a
/// ceiling over it and can only narrow, so a bundle may pin a kind or forbid
/// one and a user's own file cannot climb back out.
fn resolveSearch(
    arena: std.mem.Allocator,
    io: std.Io,
    config_dir: []const u8,
    org_bundle: ?*const chock_policy.org.Bundle,
) StartError!chock_policy.search.Search {
    var diag: ?chock_policy.search.Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);

    const operator = chock_policy.search.loadOperator(arena, io, config_dir, &diag) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        if (diag) |*d| {
            tty.print(.err, "chock run: the search block could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the search block could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };

    const ceiling = if (org_bundle) |bundle| bundle.search else null;
    return chock_policy.search.foldLayers(operator, ceiling, &diag) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        if (diag) |*d| {
            tty.print(.err, "chock run: the org bundle does not permit this search engine: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the org bundle does not permit this search engine: {t}\n", .{err});
        }
        return error.Reported;
    };
}

test "the limits a project and an operator name reach the sandbox this run builds" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project_tmp = testing.tmpDir(.{});
    defer project_tmp.cleanup();
    var config_tmp = testing.tmpDir(.{});
    defer config_tmp.cleanup();

    {
        var file = try project_tmp.dir.createFile(io, chock_policy.limits.file_name, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, ".{ .limits = .{ .processes = 300 } }");
    }
    {
        var file = try config_tmp.dir.createFile(io, chock_policy.limits.operator_file_name, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, ".{ .limits = .{ .memory = \"1GiB\" } }");
    }

    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_len = try project_tmp.dir.realPath(io, &project_buffer);
    var config_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const config_len = try config_tmp.dir.realPath(io, &config_buffer);

    const resolved = (try resolveLimits(
        arena,
        io,
        project_buffer[0..project_len],
        config_buffer[0..config_len],
        null,
    )).?;
    try testing.expectEqual(@as(u64, 300), resolved.processes);
    try testing.expectEqual(@as(u64, 1 << 30), resolved.memory_bytes);

    var config = testConfig();
    applyLimits(&config, resolved);
    try testing.expectEqual(@as(?u64, 300), config.limits.processes);
    try testing.expectEqual(@as(?u64, 1 << 30), config.limits.memory_bytes);
}

test "a machine nobody configured still gets a number sized to it, and never a smaller one" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project_tmp = testing.tmpDir(.{});
    defer project_tmp.cleanup();
    var config_tmp = testing.tmpDir(.{});
    defer config_tmp.cleanup();

    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_len = try project_tmp.dir.realPath(io, &project_buffer);
    var config_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const config_len = try config_tmp.dir.realPath(io, &config_buffer);

    const resolved = (try resolveLimits(
        arena,
        io,
        project_buffer[0..project_len],
        config_buffer[0..config_len],
        null,
    )).?;
    try testing.expect(resolved.processes >= chock_policy.limits.default_processes);
    try testing.expect(resolved.memory_bytes >= chock_policy.limits.default_memory_bytes);
    try testing.expect(!resolved.processes_from_org);

    var config = testConfig();
    applyLimits(&config, resolved);
    try testing.expectEqual(@as(?u64, resolved.processes), config.limits.processes);
    try testing.expectEqual(@as(?u64, resolved.memory_bytes), config.limits.memory_bytes);
}

test "a limits block that does not parse stops the session rather than sizing it wrongly" {
    const gpa = testing.allocator;
    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project_tmp = testing.tmpDir(.{});
    defer project_tmp.cleanup();
    var config_tmp = testing.tmpDir(.{});
    defer config_tmp.cleanup();

    {
        var file = try project_tmp.dir.createFile(io, chock_policy.limits.file_name, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, ".{ .limits = .{ .processes = \"200%\" } }");
    }

    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_len = try project_tmp.dir.realPath(io, &project_buffer);
    var config_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const config_len = try config_tmp.dir.realPath(io, &config_buffer);

    try testing.expectError(error.Reported, resolveLimits(
        arena,
        io,
        project_buffer[0..project_len],
        config_buffer[0..config_len],
        null,
    ));

    try testing.expect(std.mem.indexOf(u8, said.err(), "chock.zon") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "processes") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "200%") != null);
}

fn testConfig() sandbox.Config {
    return .{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    };
}

/// A session above the org ceiling is refused here and not lowered, because
/// lowering it quietly leaves a project believing it has money it does not have.
fn budgetUnderOrg(
    gpa: std.mem.Allocator,
    from_file: ?chock_cost.budget.Budget,
    options: Options,
    org_bundle: ?*const chock_policy.org.Bundle,
) StartError!?chock_cost.budget.Budget {
    const asked: ?chock_cost.budget.Budget = asked: {
        const slice = options.max_cost orelse break :asked from_file;
        const currency = if (options.currency.len != 0)
            options.currency
        else if (from_file) |file| file.currency else chock_cost.budget.default_currency;

        const file_cap = from_file orelse break :asked .{
            .max_cost = slice,
            .currency = currency,
        };
        // Two caps in two currencies cannot be compared, and inventing a rate
        // would be worse than not enforcing.
        if (!std.mem.eql(u8, file_cap.currency, currency)) {
            break :asked .{ .max_cost = slice, .currency = currency };
        }
        break :asked .{
            .max_cost = @min(file_cap.max_cost, slice),
            .currency = currency,
        };
    };

    var diag: ?chock_cost.budget.Diagnostic = null;
    // Neither variant this call can raise owns memory today. `deinit` is still
    // called, because a caller that asks which variant it holds before releasing
    // it breaks the day a variant that does own memory is added.
    defer if (diag) |*d| d.deinit(gpa);
    return chock_cost.budget.underCeiling(
        asked,
        orgBudgetCeiling(org_bundle),
        &diag,
    ) catch {
        if (diag) |*d| {
            tty.print(.err, "chock run: {f}\n", .{d});
        } else {
            tty.print(
                .err,
                "chock run: the budget is above the ceiling this installation's org policy " ++
                    "bundle sets.\n",
                .{},
            );
        }
        return error.Reported;
    };
}

fn spawnChain(options: Options) []const chock_proto.event.SpawnLink {
    return options.parent_chain;
}

/// Read from the command line and never from the log: `chock run --continue`
/// names no kind.
fn agentRole(options: Options) chock_core.tools.Role {
    return if (chock_broker.review.isArbitrator(options.agent_kind)) .arbitrator else .worker;
}

fn prepareScratchpad(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    id: []const u8,
    options: Options,
) ?[]const u8 {
    if (options.scratchpad.len != 0) {
        var diag: ?chock_core.Diagnostic = null;
        defer if (diag) |*fault| fault.deinit(gpa);
        chock_core.scratchpad.makeLayout(
            io,
            options.scratchpad,
            chock_core.scratchpad.sinkOf(gpa, &diag),
        ) catch {
            if (diag) |fault| {
                tty.print(
                    .warn,
                    "chock run: the scratchpad {s} this session was given could not be built ({f}), " ++
                        "so it runs with the TMPDIR it was given and can start no command in the " ++
                        "background.\n",
                    .{ options.scratchpad, fault },
                );
            } else {
                tty.print(
                    .warn,
                    "chock run: the scratchpad {s} this session was given could not be built, so it " ++
                        "runs with the TMPDIR it was given and can start no command in the background.\n",
                    .{options.scratchpad},
                );
            }
            return null;
        };
        return options.scratchpad;
    }

    const dir = session_paths.scratchpadDir(arena, env, id) catch {
        tty.print(
            .warn,
            "chock run: the scratchpad directory is unknown, so tool calls have nowhere but " ++
                "the workspace to write and no command can run in the background.\n",
            .{},
        );
        return null;
    };

    var made_diag: ?chock_core.Diagnostic = null;
    defer if (made_diag) |*fault| fault.deinit(gpa);
    chock_core.scratchpad.makeLayout(io, dir, chock_core.scratchpad.sinkOf(gpa, &made_diag)) catch {
        if (made_diag) |fault| tty.print(.warn, "chock run: {f}\n", .{fault});
        tty.print(
            .warn,
            "chock run: the scratchpad {s} could not be made, so this session runs with the " ++
                "TMPDIR it was given and can start no command in the background.\n",
            .{dir},
        );
        return null;
    };
    return dir;
}

/// The spelling of `dir` a sandbox rule can act on, or null for a directory that
/// was never made. A build that moves no path turns a mount into a rule, and a
/// rule matches the path the kernel resolved: macOS reaches `$TMPDIR` below
/// `/var`, a link to `/private/var`, so a rule on the unresolved spelling
/// matches nothing and every tool call reads as refused.
fn resolvedForSandbox(arena: std.mem.Allocator, io: std.Io, dir: ?[]const u8) ?[]const u8 {
    const path = dir orelse return null;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const resolved = sandbox.resolvedPath(io, path, &buffer);
    if (std.mem.eql(u8, resolved, path)) return path;
    return arena.dupe(u8, resolved) catch path;
}

fn prepareCache(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) ?[]const u8 {
    const dir = session_paths.cacheDir(arena, env, project_root) catch |err| {
        tty.print(
            .warn,
            "chock run: the toolchain cache directory is unknown ({t}), so tool calls have " ++
                "nowhere but the workspace to write.\n",
            .{err},
        );
        return null;
    };

    var diag: ?chock_core.Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);
    const is_new = session_paths.createCacheDir(
        io,
        dir,
        chock_core.cache.sinkOf(gpa, &diag),
    ) catch {
        if (diag) |fault| {
            tty.print(
                .warn,
                "chock run: the toolchain cache {s} could not be made ({f}), so a compiler in " ++
                    "this session has nowhere but the workspace to write.\n",
                .{ dir, fault },
            );
        } else {
            tty.print(
                .warn,
                "chock run: the toolchain cache {s} could not be made, so a compiler in this " ++
                    "session has nowhere but the workspace to write.\n",
                .{dir},
            );
        }
        return null;
    };

    if (is_new) {
        tty.print(
            .plain,
            "chock: this project has no toolchain cache yet, so one is made at {s}. " ++
                "`chock cache clear` empties it.\n",
            .{dir},
        );
        return dir;
    }

    const size = chock_core.cache.measure(arena, io, dir, chock_core.cache.max_bytes);
    if (chock_core.cache.verdictFor(size) == .empty) {
        const went = chock_core.cache.clear(arena, io, dir, chock_core.cache.sinkOf(gpa, &diag)) catch {
            if (diag) |fault| {
                tty.print(
                    .warn,
                    "chock: the toolchain cache {s} is over its bound and could not be emptied ({f})\n",
                    .{ dir, fault },
                );
            } else {
                tty.print(
                    .warn,
                    "chock: the toolchain cache {s} is over its bound and could not be emptied\n",
                    .{dir},
                );
            }
            return dir;
        };
        tty.print(
            .warn,
            "chock: the toolchain cache {s} held {d} MiB, over the bound of {d} MiB, so it was " ++
                "emptied. This session builds from nothing.\n",
            .{ dir, went.bytes / (1024 * 1024), chock_core.cache.max_bytes / (1024 * 1024) },
        );
        return dir;
    }
    if (size.files != 0) {
        tty.detail("chock: toolchain cache {d} MiB in {d} files ({s})\n", .{
            size.bytes / (1024 * 1024),
            size.files,
            dir,
        });
    }
    return dir;
}

fn loadDevShell(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    cache_dir: ?[]const u8,
    shell_name: ?[]const u8,
) StartError!?chock_nix.DevShell {
    const dir = cache_dir orelse return null;

    if (shell_name) |name| {
        tty.detail("chock: the dev shell is the {s} attribute of this flake\n", .{name});
    }

    var diag: ?chock_nix.Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    const loaded = chock_nix.DevShell.load(gpa, io, .{
        .project_root = project_root,
        .cache_dir = dir,
        .shell_name = shell_name,
        .host_env = env,
        .on_evaluate = reportEvaluatingDevShell,
        .diag = &diag,
    }) catch |err| loaded: {
        if (diag) |*fault| {
            tty.print(.err, "chock: this project's dev shell could not be read: {f}\n", .{fault});
        } else {
            tty.print(.err, "chock: this project's dev shell could not be read ({t})\n", .{err});
        }
        // A project with a flake this cannot read still runs, under the host's
        // own environment. A named attribute does not: a session that asked
        // for one environment and got another is the fault this refuses.
        if (shell_name) |name| {
            tty.print(
                .err,
                "chock: nothing named {s} could be read, so this session stops. " ++
                    "`nix develop {s}#{s}` says the same thing.\n",
                .{ name, project_root, name },
            );
            return error.Reported;
        }
        break :loaded null;
    };

    // A session whose toolchain is not rooted breaks under a
    // `nix-collect-garbage` that runs while it does.
    if (loaded != null) {
        if (diag) |*notice| tty.print(.warn, "chock: {f}\n", .{notice});
    }

    if (loaded) |shell| {
        tty.detail("chock: dev shell {s}: {d} variables, {d} store paths mounted\n", .{
            if (shell.evaluated) "evaluated" else "cached",
            shell.variables.len,
            shell.store_paths.len,
        });
    }
    return loaded;
}

fn devShellDirFor(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) ?[]const u8 {
    const dir = session_paths.devShellDir(arena, env, project_root) catch |err| {
        tty.print(
            .warn,
            "chock: the dev shell directory is unknown ({t}), so this session has no dev shell\n",
            .{err},
        );
        return null;
    };
    session_paths.createDevShellDir(io, dir) catch return null;
    return dir;
}

fn reportEvaluatingDevShell(project_root: []const u8) void {
    tty.print(.plain, "chock: reading the dev shell of {s} with nix\n", .{project_root});
}

// The host's own system directories are the third answer because `/nix/store` is
// a bind source that is not there on a machine with no Nix, so every tool call
// of such a session died with `MountTreeFailed`. They are read only, they reach
// no home directory, and a machine with none of them is refused at session start.

const Toolchain = struct {
    store_paths: []const []const u8 = &.{},
    mounts: []const chock_core.tools.ToolchainMount = &.{},
    which: Which,

    const Which = enum { dev_shell, image, host };
};

/// The host directories a session mounts when the project states no toolchain of
/// its own, each read only. `/etc` is the one entry that is not obviously a
/// toolchain: Debian resolves `/usr/bin/cc` through `/etc/alternatives`, glibc
/// reads `/etc/ld.so.cache` to find a shared library, and TLS needs the
/// certificates at `/etc/ssl/certs`. A routed tool call takes this one directory
/// for itself, because it has to write a `resolv.conf` into it.
pub const host_toolchain_candidates: []const []const u8 = &.{
    "/nix/store",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/etc",
    "/opt",
};

fn hostToolchainPaths(
    arena: std.mem.Allocator,
    io: std.Io,
) std.mem.Allocator.Error![]const []const u8 {
    if (pathIsDirectory(io, host_toolchain_candidates[0])) {
        return arena.dupe([]const u8, host_toolchain_candidates[0..1]);
    }

    var found: std.ArrayList([]const u8) = .empty;
    for (host_toolchain_candidates[1..]) |path| {
        // A symbolic link counts: `/bin` is a link into `/usr` on Debian and on
        // Arch, and a bind mount follows it.
        if (!pathIsDirectory(io, path)) continue;
        try found.append(arena, path);
    }
    return found.toOwnedSlice(arena);
}

fn pathIsDirectory(io: std.Io, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .directory;
}

/// The mount set of a container image, minus any entry that would sit above
/// something the sandbox puts there itself. `.dockerenv` is a regular file at the
/// top of a real Debian image tree, and Landlock answers `EINVAL` for a directory
/// right over a file. An image entry that is a strict ancestor of another mount's
/// target breaks both orders: the image first leaves `mkdirat` answering `EROFS`
/// inside a read only `/home`, and the image second covers the workspace.
fn imageToolchainMounts(
    arena: std.mem.Allocator,
    image: *const chock_container.Image,
    sandbox_mounts: []const sandbox.namespace.Mount,
) std.mem.Allocator.Error!ImageMounts {
    var kept: std.ArrayList(chock_core.tools.ToolchainMount) = .empty;
    var dropped: std.ArrayList([]const u8) = .empty;

    for (image.mounts) |one| {
        if (isAboveAMount(one.target, sandbox_mounts)) {
            try dropped.append(arena, one.target);
            continue;
        }
        try kept.append(arena, .{
            .source = one.source,
            .target = one.target,
            .kind = switch (one.kind) {
                .directory => .directory,
                .file => .file,
            },
        });
    }

    return .{
        .mounts = try kept.toOwnedSlice(arena),
        .dropped = try dropped.toOwnedSlice(arena),
    };
}

const ImageMounts = struct {
    mounts: []const chock_core.tools.ToolchainMount,
    dropped: []const []const u8,
};

fn isAboveAMount(target: []const u8, mounts: []const sandbox.namespace.Mount) bool {
    for (mounts) |mount| {
        const other = switch (mount) {
            .bind => |b| b.target,
            .overlay => |o| o.target,
            .proc => |p| p.target,
            .deny => |d| d.target,
        };
        if (other.len <= target.len) continue;
        if (!std.mem.startsWith(u8, other, target)) continue;
        if (other[target.len] != '/') continue;
        return true;
    }
    return false;
}

/// `PATH` is rewritten to name the tree on the host, because this resolution
/// happens before any sandbox exists and the image's own `PATH` names paths
/// inside one. An image that states no `PATH` gets none.
fn imageToolEnvironment(
    arena: std.mem.Allocator,
    image: *const chock_container.Image,
) std.mem.Allocator.Error!*std.process.Environ.Map {
    const map = try arena.create(std.process.Environ.Map);
    map.* = std.process.Environ.Map.init(arena);

    for (image.variables) |record| {
        const equals = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (equals == 0) continue;
        const key = record[0..equals];
        const value = record[equals + 1 ..];
        if (!std.mem.eql(u8, key, "PATH")) {
            try map.put(key, value);
            continue;
        }
        try map.put(key, try hostSearchPath(arena, image.rootfs, value));
    }
    return map;
}

fn hostSearchPath(
    arena: std.mem.Allocator,
    rootfs: []const u8,
    search: []const u8,
) std.mem.Allocator.Error![]const u8 {
    var built: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, search, ':');
    while (it.next()) |entry| {
        if (entry.len == 0 or entry[0] != '/') continue;
        if (built.items.len != 0) try built.append(arena, ':');
        try built.appendSlice(arena, rootfs);
        try built.appendSlice(arena, entry);
    }
    return built.toOwnedSlice(arena);
}

/// The workspace's own variables win, because its git variables are what make git
/// work at all against a read only object store.
fn imageSandboxEnvironment(
    arena: std.mem.Allocator,
    workspace_env: []const []const u8,
    image: *const chock_container.Image,
) std.mem.Allocator.Error![]const []const u8 {
    var entries: std.ArrayList([]const u8) = .empty;
    try entries.appendSlice(arena, workspace_env);

    for (image.variables) |record| {
        const equals = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        const key = record[0..equals];
        if (key.len == 0) continue;
        if (namesKey(workspace_env, key)) continue;
        try entries.append(arena, record);
    }

    return entries.toOwnedSlice(arena);
}

/// Every refusal here happens at session start, because a tool call has no
/// network and no daemon socket. The `Image` owns the strings the mount set and
/// both environments borrow.
fn loadImage(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) !?chock_container.Image {
    const named = switch (chock_container.config.load(arena, io, project_root) catch |err| {
        tty.print(
            .err,
            "chock run: the container block of this project's chock.zon could not be read ({t}). " ++
                "Fix the file, or remove the block to use this machine's own toolchain.\n",
            .{err},
        );
        return error.Reported;
    }) {
        .none => return null,
        .refused => |text| {
            tty.print(.err, "chock run: {s}\n", .{text});
            return error.Reported;
        },
        .named => |reference| reference,
    };

    // The arena owns the message and never the library's own working allocator:
    // `Image.load` builds a private arena and destroys it on every error path,
    // so a message built from that one is read after the free.
    var diag: ?chock_container.Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);
    const sink = chock_container.sinkOf(arena, &diag);

    const found = switch (chock_container.Runtime.detect(arena, io, env, &diag) catch |err| {
        tty.print(
            .err,
            "chock run: this project names the image {s} and its runtime could not be run ({t}).\n",
            .{ named, err },
        );
        return error.Reported;
    }) {
        .not_installed => {
            tty.print(
                .err,
                "chock run: this project names the image {s}, and {s}\n",
                .{ named, try chock_container.Runtime.notInstalledText(arena) },
            );
            return error.Reported;
        },
        .refused => |refusal| {
            tty.print(.err, "chock run: {s}\n", .{refusal.text});
            return error.Reported;
        },
        .ready => |value| value,
    };

    const dir_name = try chock_container.reference.directoryName(arena, named);
    const cache_dir = session_paths.imageDir(arena, env, dir_name) catch |err| {
        tty.print(
            .err,
            "chock run: the directory for the image {s} is unknown ({t}), so it cannot be read.\n",
            .{ named, err },
        );
        return error.Reported;
    };
    session_paths.createImageDir(io, cache_dir) catch |err| {
        tty.print(
            .err,
            "chock run: the directory {s} could not be made ({t}), so the image {s} cannot be read.\n",
            .{ cache_dir, err, named },
        );
        return error.Reported;
    };

    var host = found.host(env, sink);
    const answer = chock_container.Image.load(gpa, io, .{
        .reference = named,
        .cache_dir = cache_dir,
        .kind = found.kind,
        .trust = found.trust,
        .runner = host.runner(),
        .on_extract = reportExtractingImage,
        .on_wait = reportWaitingForImage,
        .diag = sink,
    }) catch |err| {
        if (diag) |*fault| {
            tty.print(.err, "chock run: the image {s} could not be read: {f}\n", .{ named, fault });
        } else {
            tty.print(.err, "chock run: the image {s} could not be read ({t})\n", .{ named, err });
        }
        return error.Reported;
    };

    switch (answer) {
        .refused => |text| {
            defer gpa.free(text);
            tty.print(.err, "chock run: {s}\n", .{text});
            return error.Reported;
        },
        .provided => |image| {
            if (diag) |*notice| tty.print(.warn, "chock: {f}\n", .{notice});
            return image;
        },
    }
}

test "the one act an agent may ask for is spelled the same in all three places" {
    try std.testing.expectEqualStrings(
        chock_broker.actions.Kind.workspace_apply.wireName(),
        chock_core.handback.apply_action,
    );
    try std.testing.expectEqualStrings(
        chock_broker.actions.self_asked_tool,
        chock_core.Loop.request_tool_name,
    );
}

test "a machine with a nix store gets only that, and one without gets its own system directories" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const paths = try hostToolchainPaths(arena, std.testing.io);

    if (pathIsDirectory(std.testing.io, "/nix/store")) {
        try std.testing.expectEqual(@as(usize, 1), paths.len);
        try std.testing.expectEqualStrings("/nix/store", paths[0]);
        return;
    }

    try std.testing.expect(paths.len != 0);
    for (paths) |path| try std.testing.expect(!std.mem.eql(u8, path, "/nix/store"));
}

test "every host candidate is absolute, so a session's mount set cannot depend on a working directory" {
    for (host_toolchain_candidates) |path| {
        try std.testing.expect(std.fs.path.isAbsolute(path));
    }
}

test "an image's own PATH is rewritten to the tree on the host" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const built = try hostSearchPath(arena, "/state/images/alpine-3-20/rootfs", "/usr/bin:/bin");
    try std.testing.expectEqualStrings(
        "/state/images/alpine-3-20/rootfs/usr/bin:/state/images/alpine-3-20/rootfs/bin",
        built,
    );

    const filtered = try hostSearchPath(arena, "/tree", "/usr/bin:.:bin");
    try std.testing.expectEqualStrings("/tree/usr/bin", filtered);

    const empty = try hostSearchPath(arena, "/tree", "");
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "an image's mount kinds carry through, because landlock refuses a directory right over a file" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const mounts = [_]chock_container.Image.Mount{
        .{ .source = "/tree/usr", .target = "/usr", .kind = .directory },
        .{ .source = "/tree/.dockerenv", .target = "/.dockerenv", .kind = .file },
    };
    const image = chock_container.Image{
        .arena = undefined,
        .kind = .docker,
        .trust = .root_daemon,
        .reference = "debian:stable-slim",
        .digest = "sha256:aaa",
        .variables = &.{},
        .workdir = "/",
        .rootfs = "/tree",
        .mounts = &mounts,
        .extracted = false,
        .in_use = undefined,
    };

    const built = try imageToolchainMounts(arena, &image, &.{});
    try std.testing.expectEqual(@as(usize, 2), built.mounts.len);
    try std.testing.expectEqual(@as(usize, 0), built.dropped.len);
    try std.testing.expectEqual(chock_core.tools.ToolchainMount.Kind.directory, built.mounts[0].kind);
    try std.testing.expectEqual(chock_core.tools.ToolchainMount.Kind.file, built.mounts[1].kind);
    try std.testing.expectEqualStrings("/tree/usr", built.mounts[0].source);
    try std.testing.expectEqualStrings("/usr", built.mounts[0].target);
}

test "an image entry above a mount the sandbox makes itself is left out and said out loud" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const image_mounts = [_]chock_container.Image.Mount{
        .{ .source = "/tree/home", .target = "/home", .kind = .directory },
        .{ .source = "/tree/usr", .target = "/usr", .kind = .directory },
    };
    const image = chock_container.Image{
        .arena = undefined,
        .kind = .podman,
        .trust = .user_only,
        .reference = "alpine:3.20",
        .digest = "sha256:ccc",
        .variables = &.{},
        .workdir = "/",
        .rootfs = "/tree",
        .mounts = &image_mounts,
        .extracted = false,
        .in_use = undefined,
    };

    const sandbox_mounts = [_]sandbox.namespace.Mount{.{ .bind = .{
        .source = "/state/01.work/wt",
        .target = "/home/somebody/project",
        .read_only = false,
    } }};

    const built = try imageToolchainMounts(arena, &image, &sandbox_mounts);
    try std.testing.expectEqual(@as(usize, 1), built.mounts.len);
    try std.testing.expectEqualStrings("/usr", built.mounts[0].target);
    try std.testing.expectEqual(@as(usize, 1), built.dropped.len);
    try std.testing.expectEqualStrings("/home", built.dropped[0]);

    try std.testing.expect(!isAboveAMount("/ho", &sandbox_mounts));
    try std.testing.expect(!isAboveAMount("/home/somebody/project", &sandbox_mounts));
}

test "an image session keeps the workspace's own variables and carries the image's PATH" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const workspace_env = [_][]const u8{ "GIT_OBJECT_DIRECTORY=/run/chock/git/objects", "KEEP=me" };
    const variables = [_][]const u8{
        "GIT_OBJECT_DIRECTORY=/somewhere/an/image/chose",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "LANG=C.UTF-8",
    };
    const image = chock_container.Image{
        .arena = undefined,
        .kind = .podman,
        .trust = .user_only,
        .reference = "alpine:3.20",
        .digest = "sha256:bbb",
        .variables = &variables,
        .workdir = "/",
        .rootfs = "/tree",
        .mounts = &.{},
        .extracted = true,
        .in_use = undefined,
    };

    const built = try imageSandboxEnvironment(arena, &workspace_env, &image);
    try std.testing.expectEqual(@as(usize, 4), built.len);
    try std.testing.expectEqualStrings("GIT_OBJECT_DIRECTORY=/run/chock/git/objects", built[0]);
    try std.testing.expectEqualStrings("KEEP=me", built[1]);
    try std.testing.expectEqualStrings("PATH=/usr/local/bin:/usr/bin:/bin", built[2]);
    try std.testing.expectEqualStrings("LANG=C.UTF-8", built[3]);

    const tool_env = try imageToolEnvironment(arena, &image);
    try std.testing.expectEqualStrings("/tree/usr/local/bin:/tree/usr/bin:/tree/bin", tool_env.get("PATH").?);
    try std.testing.expectEqualStrings("C.UTF-8", tool_env.get("LANG").?);
}

fn reportExtractingImage(reference: []const u8) void {
    tty.print(.plain, "chock: writing the files of {s} to disk, once\n", .{reference});
}

fn reportWaitingForImage(reference: []const u8) void {
    tty.print(
        .plain,
        "chock: another session is writing the files of {s} to disk. Waiting for it\n",
        .{reference},
    );
}

/// The trust position of an image is its own line and never a layer. A root
/// daemon that unpacked the image is a weaker trust position, not a broken
/// sandbox, and `chock_sandbox.guarantees` is unchanged either way.
fn toolchainFor(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    dev_shell: ?chock_nix.DevShell,
    image: ?*const chock_container.Image,
    sandbox_mounts: []const sandbox.namespace.Mount,
) !Toolchain {
    if (image) |one| {
        const built = try imageToolchainMounts(arena, one, sandbox_mounts);
        tty.detail("chock: image {s}: {s}, {d} variables, {d} paths mounted\n", .{
            one.reference,
            if (one.extracted) "extracted" else "already on disk",
            one.variables.len,
            built.mounts.len,
        });
        for (built.dropped) |target| {
            tty.print(
                .warn,
                "chock: the image's own {s} is not mounted, because this session puts its own " ++
                    "directories under it. It is empty in a base image.\n",
                .{target},
            );
        }
        if (one.trust.isPrivileged()) {
            tty.print(
                .warn,
                "chock: {s} unpacked this image and {s}. The sandbox a tool call runs in is " ++
                    "unchanged.\n",
                .{ one.kind.displayName(), one.trust.text() },
            );
        }
        return .{ .mounts = built.mounts, .which = .image };
    }

    if (dev_shell) |shell| {
        return .{ .store_paths = shell.store_paths, .which = .dev_shell };
    }

    const paths = try hostToolchainPaths(arena, io);
    if (paths.len == 0) {
        tty.print(
            .err,
            "chock run: this machine has no directory a tool call could run a program from. " ++
                "None of the usual system directories is there, this project states no dev shell, " ++
                "and its chock.zon names no container image. A session would start and every tool " ++
                "call in it would fail, so it does not start. Give the project a flake.nix with a " ++
                "dev shell, or a chock.zon holding .container = .{{ .image = \"...\" }}.\n",
            .{},
        );
        return error.Reported;
    }

    tty.print(
        .warn,
        "chock: {s} states no toolchain, so tool calls use this machine's own programs and the " ++
            "sandbox mounts {d} of its system directories, read only. Narrow it with a flake.nix " ++
            "dev shell, or with .container = .{{ .image = \"...\" }} in chock.zon.\n",
        .{ project_root, paths.len },
    );
    return .{ .store_paths = paths, .which = .host };
}

const Provisioning = struct {
    nix_program: []const u8,
    nix_store_program: ?[]const u8,
    /// The flake registry entry, so a user who pinned `nixpkgs` gets programs
    /// from the revision they pinned. Chock resolves what the user's own Nix
    /// resolves, and the model does not choose this.
    registry: []const u8,
    root_dir: ?[]const u8,
};

const provision_action = chock_broker.actions.Kind.nix_build.wireName();

/// Whether this session may add a program to its toolchain, and what it needs to
/// do it. Read once, at the start: `Loop.run` holds the exclusive lock on the
/// log for the whole session, so nothing can append an answer while a turn is
/// running and a mid-session question can only time out. A project with no
/// `chock.zon` therefore cannot provision.
fn provisionDecision(
    arena: std.mem.Allocator,
    policy: *const chock_policy.table.Table,
    chain_links: []const chock_proto.event.SpawnLink,
    agent_kind: []const u8,
    model: []const u8,
) std.mem.Allocator.Error!chock_policy.table.Decision {
    const chain = try arena.alloc([]const u8, chain_links.len + 1);
    defer arena.free(chain);
    for (chain_links, chain[0..chain_links.len]) |link, *slot| slot.* = link.agent_kind;
    chain[chain_links.len] = agent_kind;

    var fault: ?chock_policy.table.ChainFault = null;
    const decision = policy.evaluateChain(chain, .{
        .agent_kind = agent_kind,
        .model = model,
        .tool = @tagName(chock_core.tools.Tool.provide_tool),
        .action = provision_action,
    }, &fault);
    if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});
    return decision;
}

fn languageServerPermitted(
    arena: std.mem.Allocator,
    policy: *const chock_policy.table.Table,
    chain_links: []const chock_proto.event.SpawnLink,
    agent_kind: []const u8,
    model: []const u8,
    command: []const []const u8,
) std.mem.Allocator.Error!bool {
    var buffer: [chock_core.lsp_driver.max_action_bytes]u8 = undefined;
    const action = chock_core.lsp_driver.actionInto(&buffer, command) orelse {
        tty.print(
            .warn,
            "chock run: the language server is off: its program cannot be one label of a policy " ++
                "rule, so no rule could have permitted it. The last part of the path has to be " ++
                "letters, digits, hyphen and underscore.\n",
            .{},
        );
        return false;
    };

    const chain = try arena.alloc([]const u8, chain_links.len + 1);
    defer arena.free(chain);
    for (chain_links, chain[0..chain_links.len]) |link, *slot| slot.* = link.agent_kind;
    chain[chain_links.len] = agent_kind;

    var fault: ?chock_policy.table.ChainFault = null;
    const decision = policy.evaluateChain(chain, .{
        .agent_kind = agent_kind,
        .model = model,
        .tool = chock_core.lsp_driver.policy_tool,
        .action = action,
    }, &fault);
    if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});

    if (decision == .allow) return true;
    tty.detail(
        "chock: the language server is off, because this project's policy answers {t} for {s}\n",
        .{ decision, action },
    );
    return false;
}

/// Only `allow` exposes a device, and only a device this project named in its own
/// `devices` block is ever asked about at all.
/// `chock_core.devices.HostSource.scan` calls this seam for every USB or serial
/// device the machine has plugged in, named or not, because it cannot tell the
/// difference from sysfs alone, and `declared` draws the line.
const DevicePolicySeam = struct {
    policy: *const chock_policy.table.Table,
    chain: []const []const u8,
    agent_kind: []const u8,
    model: []const u8,
    declared: []const chock_core.devices.Settings,

    fn seam(self: *DevicePolicySeam) chock_core.devices.PolicySeam {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.devices.PolicySeam.VTable{ .permitted = permittedFn };

    fn permittedFn(ptr: *anyopaque, action: []const u8) bool {
        const self: *DevicePolicySeam = @ptrCast(@alignCast(ptr));
        return self.decisionFor(action) == .allow;
    }

    fn decisionFor(self: *const DevicePolicySeam, action: []const u8) chock_policy.table.Decision {
        var named = false;
        for (self.declared) |one| {
            if (std.mem.eql(u8, one.action, action)) {
                named = true;
                break;
            }
        }
        if (!named) return .ask;

        var fault: ?chock_policy.table.ChainFault = null;
        const decision = self.policy.evaluateChain(self.chain, .{
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = chock_policy.devices.policy_tool,
            .action = action,
        }, &fault);
        if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});
        return decision;
    }
};

/// Every field is null together when this project named no device, so a
/// `Sandbox.spawn` that reads this session's config never binds `/dev`, never
/// forks the device helper, and never polls an extra descriptor.
const DeviceWiring = struct {
    seam: ?*DevicePolicySeam = null,
    host: ?*chock_core.devices.HostSource = null,
    device_tree: ?sandbox.Config.DeviceTree = null,
};

fn devicesFor(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    policy: *const chock_policy.table.Table,
    chain_links: []const chock_proto.event.SpawnLink,
    agent_kind: []const u8,
    model: []const u8,
    declared: ?[]const chock_core.devices.Settings,
) std.mem.Allocator.Error!DeviceWiring {
    const list = declared orelse return .{};

    const chain = try arena.alloc([]const u8, chain_links.len + 1);
    for (chain_links, chain[0 .. chain.len - 1]) |link, *slot| slot.* = link.agent_kind;
    chain[chain.len - 1] = agent_kind;

    const seam = try arena.create(DevicePolicySeam);
    seam.* = .{
        .policy = policy,
        .chain = chain,
        .agent_kind = agent_kind,
        .model = model,
        .declared = list,
    };

    if (!sandbox.expresses.device_passthrough) return .{ .seam = seam };

    const host = try arena.create(chock_core.devices.HostSource);
    host.* = chock_core.devices.HostSource.init(gpa, io, seam.seam());
    return .{
        .seam = seam,
        .host = host,
        // The hidden tree is the host's own `/dev`, mirrored, so a node's path
        // relative to it is what `DEVNAME` already gives. Never granted through
        // `sandbox_config.rules`: Landlock is an allowlist, so a path this
        // session never names cannot be opened, listed or resolved through, even
        // though the bind is really there after the pivot.
        .device_tree = .{ .host = "/dev", .inside = "/.chock-device-tree" },
    };
}

/// Read the `workspace` block, find what each name matches, and resolve every
/// match to the real path a mount source has to name.
///
/// Before the workspace is built, because a block this cannot honour refuses
/// the session rather than half building one.
fn workspaceBinds(
    arena: std.mem.Allocator,
    io: std.Io,
    policy: *const chock_policy.table.Table,
    chain_links: []const chock_proto.event.SpawnLink,
    agent_kind: []const u8,
    model: []const u8,
    project_root: []const u8,
) StartError![]chock_policy.workspace.Resolved {
    const block_mod = chock_policy.workspace;

    var diag: ?block_mod.Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);
    const block = block_mod.load(arena, io, project_root, &diag) catch |err| {
        if (diag) |*d| {
            tty.print(.err, "chock run: the workspace block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the workspace block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };
    if (block.binds.len == 0) return &.{};

    // The real path, because every match is compared against it and a project
    // reached through a link would make every one of them look outside.
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = std.Io.Dir.cwd().realPathFile(io, project_root, &root_buffer) catch |err| {
        tty.print(.err, "chock run: {s} could not be resolved: {t}\n", .{ project_root, err });
        return error.Reported;
    };
    const root = root_buffer[0..length];

    const chain = try arena.alloc([]const u8, chain_links.len + 1);
    for (chain_links, chain[0 .. chain.len - 1]) |link, *slot| slot.* = link.agent_kind;
    chain[chain.len - 1] = agent_kind;

    var out: std.ArrayList(chock_policy.workspace.Resolved) = .empty;
    for (block.binds) |bind| {
        const action = try bind.actionName(arena);
        var fault: ?chock_policy.table.ChainFault = null;
        const table_says = policy.evaluateChain(chain, .{
            .agent_kind = agent_kind,
            .model = model,
            .tool = chock_broker.actions.self_asked_tool,
            .action = action,
        }, &fault);
        if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});

        if (table_says == .deny) {
            tty.print(
                .warn,
                "chock run: the bind {s} is not made, because this session's policy denies {s}.\n",
                .{ bind.name, action },
            );
            continue;
        }

        const matches = try matchesFor(arena, io, root, bind.name);
        if (matches.len == 0) {
            if (bind.isRequired()) {
                tty.print(
                    .err,
                    "chock run: the bind {s} matches nothing under {s}, and a bind that names a " ++
                        "path is required. Write `.required = false` on it to carry on without it.\n",
                    .{ bind.name, project_root },
                );
                return error.Reported;
            }
            tty.detail("chock: the bind {s} matched nothing, and is not required.\n", .{bind.name});
            continue;
        }

        const permitted = narrower(table_says, decisionOf(bind.write));
        for (matches) |relative| {
            var resolved = block_mod.resolve(arena, io, root, bind, relative, &diag) catch |err| {
                if (diag) |*d| {
                    tty.print(.err, "chock run: {f}\n", .{d});
                } else {
                    tty.print(.err, "chock run: the bind {s} could not be resolved: {t}\n", .{ bind.name, err });
                }
                return error.Reported;
            };
            resolved.read_only = bind.mode != .write or permitted != .allow;
            resolved.write_back = bind.mode == .copy and permitted != .deny;
            try out.append(arena, resolved);

            tty.print(.plain, "chock: bind {s}, mode {t}, from {s}\n", .{
                resolved.relative,
                resolved.mode,
                resolved.host_path,
            });
        }
        sayWhatTheWriteDoes(bind, permitted, action);
    }
    return out.toOwnedSlice(arena);
}

fn decisionOf(write: chock_policy.workspace.Write) chock_policy.table.Decision {
    return switch (write) {
        .allow => .allow,
        .ask => .ask,
        .deny => .deny,
    };
}

fn narrower(a: chock_policy.table.Decision, b: chock_policy.table.Decision) chock_policy.table.Decision {
    return if (a.rank() <= b.rank()) a else b;
}

/// The two modes that reach the user's own disk say what they will do with a
/// change, because a bind that silently writes nothing back and a bind that
/// silently overwrites are the same line on the screen without this.
fn sayWhatTheWriteDoes(
    bind: chock_policy.workspace.Bind,
    permitted: chock_policy.table.Decision,
    action: []const u8,
) void {
    switch (bind.mode) {
        .read_only, .temp_copy => {},
        .write => if (permitted != .allow) tty.print(
            .warn,
            "chock run: the bind {s} is read only, because nothing has permitted {s} yet. " ++
                "A policy row for that action which answers allow makes it writable.\n",
            .{ bind.name, action },
        ),
        .copy => switch (permitted) {
            .allow => tty.print(
                .plain,
                "chock run: the bind {s} is written back over your own files when this " ++
                    "session's work applies.\n",
                .{bind.name},
            ),
            .deny => tty.print(
                .warn,
                "chock run: the bind {s} is never written back, because this session's policy " ++
                    "denies {s}. Its copies stay in the workspace.\n",
                .{ bind.name, action },
            ),
            else => tty.print(
                .plain,
                "chock run: the bind {s} is written back only if you permit the apply that " ++
                    "asks about it.\n",
                .{bind.name},
            ),
        },
    }
}

/// How deep a pattern may descend. A `**` in a name would otherwise walk the
/// whole project, and a project holds a `.direnv` with thousands of entries in
/// it.
const bind_max_depth: usize = 16;

/// What one name matches, as paths under the project root, sorted so the
/// session start report reads the same way twice.
///
/// The project directory and never git's own list of ignored files: a name
/// that happens to be tracked already is harmless, it is simply in the
/// workspace too.
fn matchesFor(
    arena: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    name: []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;

    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    var walker = std.mem.tokenizeScalar(u8, name, '/');
    while (walker.next()) |part| {
        if (std.mem.eql(u8, part, ".")) continue;
        try parts.append(arena, part);
    }

    try descend(arena, io, root, "", parts.items, &out);
    std.mem.sort([]const u8, out.items, {}, lessThanPath);
    return out.toOwnedSlice(arena);
}

fn lessThanPath(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn descend(
    arena: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    prefix: []const u8,
    parts: []const []const u8,
    out: *std.ArrayList([]const u8),
) std.mem.Allocator.Error!void {
    if (out.items.len >= chock_policy.workspace.max_binds) return;
    if (parts.len == 0) {
        if (prefix.len != 0) try out.append(arena, prefix);
        return;
    }
    if (std.mem.count(u8, prefix, "/") + 1 > bind_max_depth) return;

    const part = parts[0];
    const rest = parts[1..];

    if (!chock_policy.workspace.hasGlob(part)) {
        const next = try joinUnder(arena, prefix, part);
        const whole = try std.fs.path.join(arena, &.{ root, next });
        _ = std.Io.Dir.cwd().statFile(io, whole, .{}) catch return;
        return descend(arena, io, root, next, rest, out);
    }

    // A `**` matches no component at all as well as any run of them.
    const any_depth = std.mem.eql(u8, part, "**");
    if (any_depth) try descend(arena, io, root, prefix, rest, out);

    const here = try std.fs.path.join(arena, &.{ root, prefix });
    var dir = std.Io.Dir.cwd().openDir(io, here, .{ .iterate = true }) catch return;
    defer dir.close(io);

    var entries = dir.iterate();
    while (entries.next(io) catch null) |entry| {
        if (out.items.len >= chock_policy.workspace.max_binds) return;
        // git's own directory is the backing's, and `chock.zon` is bound read
        // only already. Neither is ever a match.
        if (std.mem.eql(u8, entry.name, ".git")) continue;
        const next = try joinUnder(arena, prefix, entry.name);
        if (any_depth) {
            if (entry.kind == .directory) try descend(arena, io, root, next, parts, out);
            continue;
        }
        if (!chock_core.tools.matchGlob(part, entry.name)) continue;
        try descend(arena, io, root, next, rest, out);
    }
}

fn joinUnder(
    arena: std.mem.Allocator,
    prefix: []const u8,
    name: []const u8,
) std.mem.Allocator.Error![]const u8 {
    if (prefix.len == 0) return arena.dupe(u8, name);
    return std.fs.path.join(arena, &.{ prefix, name });
}

/// Bring the resolved binds into the workspace. A path that cannot be copied
/// is one warning and not a failed session: the agent sees a workspace with
/// that one path missing, and the report says which.
///
/// A workspace this process took over copies nothing in, the same rule
/// `handleUncommitted` keeps: its copies are the last owner's agent's own.
fn attachBinds(
    arena: std.mem.Allocator,
    io: std.Io,
    workspace: *chock_workspace.Workspace,
    resolved: []const chock_policy.workspace.Resolved,
    copy_in: bool,
) StartError!void {
    if (resolved.len == 0) return;

    // The same allocator that fills the report frees it. `attachBinds` below
    // is given the arena, and the bind list it keeps outlives this call, so
    // the report's own strings come off the arena too.
    var report = chock_workspace.worktree.ImportReport{};
    defer report.deinit(arena);
    workspace.attachBinds(arena, io, resolved, copy_in, &report) catch |err| {
        tty.print(.err, "chock run: the workspace binds could not be brought in: {t}\n", .{err});
        return error.Reported;
    };
    for (report.skipped.items) |skip| {
        tty.print(.warn, "chock run: {s} was not brought across: {s}\n", .{ skip.path, skip.reason });
    }
}

test "a pattern matching nothing is fine, a literal name matching nothing stops the session" {
    const gpa = testing.allocator;
    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try project.dir.realPath(io, &buffer);
    const root = buffer[0..length];

    const table = try chock_policy.table.Table.parseUnder(arena, ".{}", &.{}, null);

    try writeChockZon(io, project.dir,
        \\.{ .workspace = .{ .binds = .{ .{ .name = "generated_*", .mode = .read_only } } } }
    );
    const nothing = try workspaceBinds(arena, io, table, &.{}, "main", "a-model", root);
    try testing.expectEqual(@as(usize, 0), nothing.len);

    try writeChockZon(io, project.dir,
        \\.{ .workspace = .{ .binds = .{ .{ .name = "generated", .mode = .read_only } } } }
    );
    try testing.expectError(
        error.Reported,
        workspaceBinds(arena, io, table, &.{}, "main", "a-model", root),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "generated") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "required") != null);
}

test "required overrides the derived answer in both directions" {
    const gpa = testing.allocator;
    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try project.dir.realPath(io, &buffer);
    const root = buffer[0..length];

    const table = try chock_policy.table.Table.parseUnder(arena, ".{}", &.{}, null);

    try writeChockZon(io, project.dir,
        \\.{ .workspace = .{ .binds = .{
        \\    .{ .name = "generated", .mode = .read_only, .required = false },
        \\} } }
    );
    const carried_on = try workspaceBinds(arena, io, table, &.{}, "main", "a-model", root);
    try testing.expectEqual(@as(usize, 0), carried_on.len);

    try writeChockZon(io, project.dir,
        \\.{ .workspace = .{ .binds = .{
        \\    .{ .name = "generated_*", .mode = .read_only, .required = true },
        \\} } }
    );
    try testing.expectError(
        error.Reported,
        workspaceBinds(arena, io, table, &.{}, "main", "a-model", root),
    );
}

test "the four modes decide what is bound read only and what is written back" {
    const gpa = testing.allocator;
    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project = testing.tmpDir(.{});
    defer project.cleanup();

    {
        var file = try project.dir.createFile(io, "config.local.json", .{});
        defer file.close(io);
        try file.writeStreamingAll(io, "CONFIG_X=y\n");
    }
    try project.dir.symLink(io, "config.local.json", "config.local.json-alias", .{});
    try project.dir.createDirPath(io, "scripts/release");
    try project.dir.createDirPath(io, "vendor/cache");
    try project.dir.createDirPath(io, "out");

    try writeChockZon(io, project.dir,
        \\.{ .workspace = .{ .binds = .{
        \\    .{ .name = "config.local.*", .mode = .read_only },
        \\    .{ .name = "scripts/release", .mode = .copy, .write = .allow },
        \\    .{ .name = "vendor/cache", .mode = .temp_copy },
        \\    .{ .name = "out", .mode = .write, .write = .allow },
        \\} } }
    );

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try project.dir.realPath(io, &buffer);
    const root = buffer[0..length];

    const table = try chock_policy.table.Table.parseUnder(arena,
        \\.{ .policy = .{ .rules = .{ .{ .action = "workspace.bind.*", .decision = .allow } } } }
    , &.{}, null);

    const resolved = try workspaceBinds(arena, io, table, &.{}, "main", "a-model", root);
    try testing.expectEqual(@as(usize, 5), resolved.len);

    // Both matches of the pattern resolve to the one real file, because the
    // second is a link to the first.
    for (resolved[0..2]) |one| {
        try testing.expectEqual(chock_policy.workspace.Mode.read_only, one.mode);
        try testing.expect(one.read_only);
        try testing.expect(!one.write_back);
        try testing.expect(std.mem.endsWith(u8, one.host_path, "/config.local.json"));
    }
    try testing.expectEqualStrings("config.local.json", resolved[0].relative);
    try testing.expectEqualStrings("config.local.json-alias", resolved[1].relative);

    try testing.expectEqual(chock_policy.workspace.Mode.copy, resolved[2].mode);
    try testing.expect(resolved[2].write_back);
    try testing.expect(resolved[2].is_directory);

    try testing.expectEqual(chock_policy.workspace.Mode.temp_copy, resolved[3].mode);
    try testing.expect(!resolved[3].write_back);

    try testing.expectEqual(chock_policy.workspace.Mode.write, resolved[4].mode);
    try testing.expect(!resolved[4].read_only);
}

test "write = .deny on a write bind makes it read only and says so" {
    const gpa = testing.allocator;
    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    try project.dir.createDirPath(io, "out");
    try writeChockZon(io, project.dir,
        \\.{ .workspace = .{ .binds = .{
        \\    .{ .name = "out", .mode = .write, .write = .deny },
        \\} } }
    );

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try project.dir.realPath(io, &buffer);
    const root = buffer[0..length];

    const table = try chock_policy.table.Table.parseUnder(arena,
        \\.{ .policy = .{ .rules = .{ .{ .action = "workspace.bind.*", .decision = .allow } } } }
    , &.{}, null);

    const resolved = try workspaceBinds(arena, io, table, &.{}, "main", "a-model", root);
    try testing.expectEqual(@as(usize, 1), resolved.len);
    try testing.expect(resolved[0].read_only);
    try testing.expect(std.mem.indexOf(u8, said.err(), "read only") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "workspace.bind.out") != null);
}

test "a bind the policy table denies is not made at all" {
    const gpa = testing.allocator;
    const io = testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    try project.dir.createDirPath(io, "out");
    try writeChockZon(io, project.dir,
        \\.{ .workspace = .{ .binds = .{ .{ .name = "out", .mode = .read_only } } } }
    );

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try project.dir.realPath(io, &buffer);
    const root = buffer[0..length];

    const org = [_]chock_policy.table.Rule{
        .{ .action = "workspace.bind.*", .decision = .deny },
    };
    const table = try chock_policy.table.Table.parseUnder(arena, ".{}", &org, null);

    const resolved = try workspaceBinds(arena, io, table, &.{}, "main", "a-model", root);
    try testing.expectEqual(@as(usize, 0), resolved.len);
    try testing.expect(std.mem.indexOf(u8, said.err(), "workspace.bind.out") != null);
}

test "a name matches against the project directory, and never against git's own" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    try project.dir.createDirPath(io, ".git");
    try project.dir.createDirPath(io, "scripts/release/deep");
    for ([_][]const u8{ "config.local.toml", "config.local.json", "other" }) |name| {
        var file = try project.dir.createFile(io, name, .{});
        defer file.close(io);
    }

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try project.dir.realPath(io, &buffer);
    const root = buffer[0..length];

    const sorted = try matchesFor(arena, io, root, "config.local.*");
    try testing.expectEqual(@as(usize, 2), sorted.len);
    try testing.expectEqualStrings("config.local.json", sorted[0]);
    try testing.expectEqualStrings("config.local.toml", sorted[1]);

    const literal = try matchesFor(arena, io, root, "scripts/release");
    try testing.expectEqual(@as(usize, 1), literal.len);
    try testing.expectEqualStrings("scripts/release", literal[0]);

    const deep = try matchesFor(arena, io, root, "scripts/**/deep");
    try testing.expectEqual(@as(usize, 1), deep.len);
    try testing.expectEqualStrings("scripts/release/deep", deep[0]);

    const everything = try matchesFor(arena, io, root, "*");
    for (everything) |one| try testing.expect(!std.mem.eql(u8, one, ".git"));
}

fn writeChockZon(io: std.Io, dir: std.Io.Dir, source: []const u8) !void {
    var file = try dir.createFile(io, chock_policy.workspace.file_name, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, source);
}

const Hardening = struct {
    decision: chock_policy.table.Decision,
    rule: chock_policy.hardening.WriteExecute,
};

fn hardeningDecision(
    arena: std.mem.Allocator,
    policy: *const chock_policy.table.Table,
    chain_links: []const chock_proto.event.SpawnLink,
    agent_kind: []const u8,
    model: []const u8,
) std.mem.Allocator.Error!Hardening {
    const chain = try arena.alloc([]const u8, chain_links.len + 1);
    defer arena.free(chain);
    for (chain_links, chain[0..chain_links.len]) |link, *slot| slot.* = link.agent_kind;
    chain[chain_links.len] = agent_kind;

    var fault: ?chock_policy.table.ChainFault = null;
    const decision = policy.evaluateChain(chain, .{
        .agent_kind = agent_kind,
        .model = model,
        .tool = chock_broker.actions.self_asked_tool,
        .action = chock_policy.hardening.jit_action,
    }, &fault);
    if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});

    const rule = chock_policy.hardening.writeExecuteFor(decision);
    if (rule == .relaxed) tty.print(
        .warn,
        "chock: the write and execute rule is off for this session, because this project's " ++
            "policy answers allow for {s}. A page can be writable and executable at the same " ++
            "time, which a run time with a just in time compiler needs. Every other layer is " ++
            "unchanged.\n",
        .{chock_policy.hardening.jit_action},
    );
    return .{ .decision = decision, .rule = rule };
}

const ApplyMode = struct {
    mode: ?chock_policy.apply.Mode = .merge,
    decision: chock_policy.table.Decision = .allow,
    asked_for: chock_policy.apply.Mode = .merge,
};

const bounded_mode_fmt = "this session's work would land as {s}, and the policy answers {t} " ++
    "for {s}, so the work waits at its ref and no branch of yours moves.";

/// A null `mode` is that an approved apply may not move a branch of the user's.
/// Read as a ceiling, so `Table.ceilingChain` is the verb and not
/// `evaluateChain`: a row nobody wrote answers `allow`, which is no ceiling.
fn applyModeFor(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    policy: *const chock_policy.table.Table,
    chain_links: []const chock_proto.event.SpawnLink,
    agent_kind: []const u8,
    model: []const u8,
) StartError!ApplyMode {
    var apply_diag: ?chock_policy.apply.Diagnostic = null;
    defer if (apply_diag) |*d| d.deinit(arena);
    const settings = chock_policy.apply.load(arena, io, project_root, &apply_diag) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        if (apply_diag) |*d| {
            tty.print(.err, "chock run: the apply block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the apply block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };

    const chain = try arena.alloc([]const u8, chain_links.len + 1);
    defer arena.free(chain);
    for (chain_links, chain[0..chain_links.len]) |link, *slot| slot.* = link.agent_kind;
    chain[chain_links.len] = agent_kind;

    var fault: ?chock_policy.table.ChainFault = null;
    const decision = policy.ceilingChain(chain, .{
        .agent_kind = agent_kind,
        .model = model,
        .tool = chock_broker.actions.self_asked_tool,
        .action = chock_policy.apply.integrate_action,
    }, &fault);
    if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});

    const bounded = chock_policy.apply.boundBy(settings.mode, decision);
    if (bounded == null) tty.print(.warn, "chock: " ++ bounded_mode_fmt ++ "\n", .{
        settings.mode.wireName(),
        decision,
        chock_policy.apply.integrate_action,
    });
    return .{ .mode = bounded, .decision = decision, .asked_for = settings.mode };
}

const FlakeInputs = struct {
    store_paths: []const []const u8 = &.{},
    missing: []const u8 = "",
    wanted: []const chock_nix.fetch.Fetch = &.{},
};

/// Two names for one host, most specific first: `nix.net.eval.com.github.443` and
/// then `nix.net.com.github.443`. The table matches a name against itself or a
/// trailing `.*`, and `patternIsWellFormed` refuses a wildcard in the middle, so
/// there is no one name that would do instead. A rule that names the phase scoped
/// key decides whatever it says, because falling through would hand a silent yes
/// to an author who asked to be prompted.
const NixTableReader = struct {
    policy: *const chock_policy.table.Table,
    chain: []const []const u8,
    agent_kind: []const u8,
    model: []const u8,
    tool: []const u8,

    fn decide(
        self: NixTableReader,
        names: chock_broker.network.NixActions,
    ) chock_policy.table.Decision {
        if (self.answer(names.phase)) |settled| return settled;
        return self.answer(names.either_phase) orelse .ask;
    }

    fn answer(self: NixTableReader, action: []const u8) ?chock_policy.table.Decision {
        var fault: ?chock_policy.table.ChainFault = null;
        const answered = self.policy.decideChain(self.chain, .{
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = self.tool,
            .action = action,
        }, &fault);
        if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});
        return if (answered.named) answered.decision else null;
    }
};

const StartupFetchGate = struct {
    policy: *const chock_policy.table.Table,
    chain: []const []const u8,
    agent_kind: []const u8,
    model: []const u8,

    fn gate(self: *StartupFetchGate) chock_nix.fetch.Gate {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_nix.fetch.Gate.VTable{
        .permit_all = permitAllFn,
        .permit_opaque = permitOpaqueFn,
        .rule_for = ruleForFn,
        .permit_site = permitSiteFn,
    };

    fn reader(self: *const StartupFetchGate) NixTableReader {
        return .{
            .policy = self.policy,
            .chain = self.chain,
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = @tagName(chock_core.tools.Tool.nix_build),
        };
    }

    fn permitAllFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        wanted: []const chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        for (wanted) |one| {
            switch (try permitFn(ptr, allocator, one)) {
                .permitted => {},
                .refused => |why| return .{ .refused = why },
            }
        }
        return .permitted;
    }

    fn permitOpaqueFn(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: []const []const u8,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        return .{ .refused = "a flake input is fetched by host and never without one" };
    }

    fn permitSiteFn(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: chock_nix.fetch.MirrorSite,
        _: chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        return .{ .refused = "a flake input names no mirror set" };
    }

    fn permitFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        one: chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        const self: *StartupFetchGate = @ptrCast(@alignCast(ptr));

        var scoped: [chock_broker.network.max_action_bytes]u8 = undefined;
        var either: [chock_broker.network.max_action_bytes]u8 = undefined;
        const names = chock_broker.network.nixActionsInto(
            &scoped,
            &either,
            phase,
            one.host,
            one.port,
        ) orelse return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} would be fetched from \"{s}\", which is not a host name a rule can be " ++
                "written for",
            .{ one.subject, one.host },
        ) };

        const decision = self.reader().decide(names);
        if (decision == .allow) return .permitted;

        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "the input {s} comes from {s}, and this project's policy answers {t} for {s}.",
            .{ one.subject, one.host, decision, names.phase },
        ) };
    }

    fn ruleForFn(ptr: *anyopaque, one: chock_nix.fetch.Fetch) chock_nix.fetch.RuleAnswer {
        const self: *StartupFetchGate = @ptrCast(@alignCast(ptr));
        var scoped: [chock_broker.network.max_action_bytes]u8 = undefined;
        var either: [chock_broker.network.max_action_bytes]u8 = undefined;
        const names = chock_broker.network.nixActionsInto(
            &scoped,
            &either,
            phase,
            one.host,
            one.port,
        ) orelse return .unsettled;
        return ruleAnswerOf(self.reader().decide(names));
    }

    const phase: chock_broker.network.NixPhase = .eval;
};

fn ruleAnswerOf(decision: chock_policy.table.Decision) chock_nix.fetch.RuleAnswer {
    return switch (decision) {
        .allow => .allow,
        .deny => .deny,
        .ask, .agent_review, .agent_then_human => .unsettled,
    };
}

fn fetchFlakeInputs(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    policy: *const chock_policy.table.Table,
    project_root: []const u8,
    chain_links: []const chock_proto.event.SpawnLink,
    agent_kind: []const u8,
    model: []const u8,
) FlakeInputs {
    const lock_bytes = readProjectLock(arena, io, project_root) orelse return .{};

    const nix_program = chock_nix.proc.resolve(arena, io, env, "nix") catch return .{
        .missing = "nix is not on this machine's PATH, so no flake input was fetched",
    };

    const chain = arena.alloc([]const u8, chain_links.len + 1) catch return .{
        .missing = "this session ran out of memory before its flake inputs were fetched",
    };
    for (chain_links, chain[0..chain_links.len]) |link, *slot| slot.* = link.agent_kind;
    chain[chain_links.len] = agent_kind;

    const wanted = switch (chock_nix.inputs.wantsOf(arena, lock_bytes) catch return .{}) {
        .hosts => |list| list,
        else => &.{},
    };

    var gate = StartupFetchGate{
        .policy = policy,
        .chain = chain,
        .agent_kind = agent_kind,
        .model = model,
    };
    var diag: ?chock_nix.Diagnostic = null;
    var host = chock_nix.provision.Host{ .nix_program = nix_program, .env = env, .diag = &diag };

    const answer = chock_nix.inputs.fetchAll(
        arena,
        io,
        host.runner(),
        gate.gate(),
        project_root,
        lock_bytes,
    ) catch {
        if (diag) |*fault| tty.print(.warn, "chock: {f}\n", .{fault});
        return .{
            .wanted = wanted,
            .missing = "the flake inputs could not be fetched, because nix could not be run",
        };
    };

    switch (answer) {
        .fetched => |paths| {
            if (paths.len != 0) {
                tty.detail("chock: {d} flake input paths are in the store\n", .{paths.len});
            }
            return .{ .store_paths = paths, .wanted = wanted };
        },
        .refused => |why| {
            tty.print(.warn, "chock: {s}\n", .{why});
            return .{ .missing = why, .wanted = wanted };
        },
    }
}

/// Read as a file an attacker may have written: every host it names goes to the
/// policy.
fn readProjectLock(arena: std.mem.Allocator, io: std.Io, project_root: []const u8) ?[]const u8 {
    const path = std.fs.path.join(arena, &.{ project_root, "flake.lock" }) catch return null;
    return std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        arena,
        .limited(chock_nix.inputs.max_lock_bytes),
    ) catch null;
}

fn provisioningFor(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    policy: *const chock_policy.table.Table,
    options: Options,
    chain_links: []const chock_proto.event.SpawnLink,
    model: []const u8,
    dev_shell_dir: ?[]const u8,
) std.mem.Allocator.Error!?Provisioning {
    const decision = try provisionDecision(arena, policy, chain_links, options.agent_kind, model);
    if (decision != .allow) {
        tty.detail(
            "chock: provide_tool is off, because this project's policy answers {t} for {s}\n",
            .{ decision, provision_action },
        );
        return null;
    }

    const nix_program = chock_nix.proc.resolve(arena, io, env, "nix") catch {
        tty.detail("chock: provide_tool is off, because nix is not on this machine's PATH\n", .{});
        return null;
    };
    const nix_store_program = chock_nix.proc.resolve(arena, io, env, "nix-store") catch null;
    if (nix_store_program == null or dev_shell_dir == null) {
        tty.print(
            .warn,
            "chock: a provisioned program cannot be held against nix-collect-garbage in this " ++
                "session, so one that runs during it can break the toolchain.\n",
            .{},
        );
    }

    return .{
        .nix_program = nix_program,
        .nix_store_program = nix_store_program,
        .registry = chock_nix.provision.default_registry,
        .root_dir = dev_shell_dir,
    };
}

fn toolEnvironment(
    arena: std.mem.Allocator,
    host_env: *std.process.Environ.Map,
    dev_shell: ?chock_nix.DevShell,
) std.mem.Allocator.Error!*std.process.Environ.Map {
    const shell = dev_shell orelse return host_env;

    const map = try arena.create(std.process.Environ.Map);
    map.* = std.process.Environ.Map.init(arena);
    for (shell.variables) |record| {
        const equals = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (equals == 0) continue;
        try map.put(record[0..equals], record[equals + 1 ..]);
    }
    return map;
}

/// The workspace's own `GIT_OBJECT_DIRECTORY` and
/// `GIT_ALTERNATE_OBJECT_DIRECTORIES` win, because they are what make git work
/// against a read only object store. Written as a skip, because two entries with
/// one name is undefined in POSIX. `PATH` is given: `cargo build` answered
/// `ENOENT` for `rustc` without it, since a child's own lookup has no dev shell
/// `PATH`. The mount set is the boundary, so a `PATH` naming store paths reaches
/// nothing that is not bound.
fn sandboxEnvironment(
    arena: std.mem.Allocator,
    workspace_env: []const []const u8,
    shell: chock_nix.DevShell,
) std.mem.Allocator.Error![]const []const u8 {
    var entries: std.ArrayList([]const u8) = .empty;
    try entries.appendSlice(arena, workspace_env);

    for (shell.variables) |record| {
        const equals = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        const key = record[0..equals];
        if (key.len == 0) continue;
        if (namesKey(workspace_env, key)) continue;
        try entries.append(arena, record);
    }

    return entries.toOwnedSlice(arena);
}

fn namesKey(entries: []const []const u8, key: []const u8) bool {
    for (entries) |entry| {
        const equals = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
        if (std.mem.eql(u8, entry[0..equals], key)) return true;
    }
    return false;
}

test "the sandbox environment keeps the workspace's own variables and carries the dev shell's PATH" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const workspace_env = [_][]const u8{ "GIT_OBJECT_DIRECTORY=/run/chock/git/objects", "KEEP=me" };
    const variables = [_][]const u8{
        "GIT_OBJECT_DIRECTORY=/somewhere/a/flake/chose",
        "PATH=/nix/store/aaa/bin",
        "ZIG_GLOBAL_CACHE_DIR=/nix/store/bbb-cache",
    };
    const shell = chock_nix.DevShell{
        .arena = undefined,
        .variables = &variables,
        .store_paths = &.{},
        .evaluated = true,
    };

    const built = try sandboxEnvironment(arena, &workspace_env, shell);

    try std.testing.expectEqual(@as(usize, 4), built.len);
    try std.testing.expectEqualStrings("GIT_OBJECT_DIRECTORY=/run/chock/git/objects", built[0]);
    try std.testing.expectEqualStrings("KEEP=me", built[1]);
    try std.testing.expectEqualStrings("PATH=/nix/store/aaa/bin", built[2]);
    try std.testing.expectEqualStrings("ZIG_GLOBAL_CACHE_DIR=/nix/store/bbb-cache", built[3]);

    try std.testing.expect(namesKey(built, "PATH"));
}

test "the tool environment is the dev shell's own, and the host's when there is none" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var host = std.process.Environ.Map.init(allocator);
    defer host.deinit();
    try host.put("PATH", "/host/bin");

    const without = try toolEnvironment(arena, &host, null);
    try std.testing.expectEqualStrings("/host/bin", without.get("PATH").?);

    const variables = [_][]const u8{"PATH=/nix/store/aaa-zig/bin"};
    const shell = chock_nix.DevShell{
        .arena = undefined,
        .variables = &variables,
        .store_paths = &.{},
        .evaluated = true,
    };
    const with = try toolEnvironment(arena, &host, shell);
    try std.testing.expectEqualStrings("/nix/store/aaa-zig/bin", with.get("PATH").?);
}

fn reportNotes(io: std.Io, started: *const Started) void {
    const dir = started.memory_dir orelse return;
    const now = chock_core.memory.count(io, dir);
    if (now == 0) return;
    if (now > started.notes_at_start) {
        tty.print(.plain, "chock: {d} new notes, {d} in all ({s})\n", .{
            now - started.notes_at_start,
            now,
            dir,
        });
        return;
    }
    tty.print(.plain, "chock: {d} notes ({s}). Read or clear them with: chock memory\n", .{ now, dir });
}

/// Resolve chock.zon's `instructions` block to real paths on disk, ready for
/// `chock_core.instructions.load`. A missing file or a link that leaves the
/// project refuses the session rather than starting one that silently
/// dropped a file the project's own configuration named.
fn projectNamedInstructions(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
) StartError![]const []const u8 {
    var diag: ?chock_policy.instructions.Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);

    const block = chock_policy.instructions.load(arena, io, project_root, &diag) catch |err| {
        if (diag) |*d| {
            tty.print(.err, "chock run: the instructions block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the instructions block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };

    const resolved = try arena.alloc([]const u8, block.files.len);
    for (block.files, 0..) |name, index_of| {
        resolved[index_of] = chock_policy.instructions.resolve(arena, io, project_root, name, &diag) catch |err| {
            if (diag) |*d| {
                tty.print(.err, "chock run: the instructions block in chock.zon could not be read: {f}\n", .{d});
            } else {
                tty.print(.err, "chock run: the instructions block in chock.zon could not be read: {t}\n", .{err});
            }
            return error.Reported;
        };
    }
    return resolved;
}

fn reportInstructions(loaded: chock_core.instructions.Loaded) void {
    if (loaded.files.len != 0) {
        tty.print(.plain, "chock: instructions", .{});
        for (loaded.files, 0..) |file, index| {
            tty.print(.plain, "{s} {s}", .{ if (index == 0) "" else ",", file.path });
        }
        tty.print(.plain, "\n", .{});
    }
    for (loaded.files) |file| {
        tty.detail("chock: instructions {s} ({t}, {d} bytes)\n", .{ file.path, file.layer, file.bytes });
    }
    if (loaded.subtrees_left_out != 0) {
        tty.print(
            .warn,
            "chock: {d} more instruction files are in this project and are not listed to the agent\n",
            .{loaded.subtrees_left_out},
        );
    }
}

fn shortId(id: []const u8) []const u8 {
    return if (id.len > 7) id[0..7] else id;
}

/// Never the branch the user has checked out. The worktree is detached exactly
/// so a session cannot move one, and a ref of the session's own is reachable and
/// inert until the user merges or cherry-picks it.
fn applyRef(gpa: std.mem.Allocator, session_id: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(gpa, "refs/chock/{s}", .{session_id});
}

const landing_options = [_][]const u8{ "merge", "rebase", "squash" };

const landing_text =
    "How should this session's work land? " ++
    "merge, rebase and squash each carry it onto the branch you have checked out. " ++
    "Anything else keeps the work at the ref, and no branch of yours moves.";

const landing_question =
    \\
    \\chock: this project asks you how the session's work should land.
    \\
    \\  merge   merge it into the branch you have checked out.
    \\  rebase  replay it on top of the branch you have checked out.
    \\  squash  put all of it on the branch you have checked out, as one commit.
    \\
    \\Anything else keeps the work at the ref, and no branch of yours moves.
    \\You are asked to approve the apply after this.
    \\Which? [merge/rebase/squash] 
;

/// The question comes before the approval and not instead of it, so the prompt a
/// person says yes to is still the one that describes the act. Nobody to ask
/// means no landing: a subagent, a session the daemon started, a `chock run`
/// whose standard input is a pipe, and one with the display up all keep the work
/// at the ref.
fn landingFor(answer: chock_core.ask.Answer) ?chock_policy.apply.Landing {
    return switch (answer) {
        .answered => |said| chock_policy.apply.Mode.fromAnswer(said),
        .declined, .nobody, .timed_out, .stopped => null,
    };
}

fn chosenLanding(
    gpa: std.mem.Allocator,
    io: std.Io,
    mode: ?chock_policy.apply.Mode,
    screen: ?*ui.Ui,
) chock_broker.integrate.Wanted {
    const asked = mode orelse return .{ .none = .policy_refused };
    if (asked.settled()) |landing| return .{ .land = landing };
    if (screen) |up| {
        var display = DisplayAsker{ .screen = up };
        const answer = display.ask(gpa, io, .{
            .text = landing_text,
            .options = &landing_options,
        }) catch return .{ .none = .nobody_answered };
        defer if (answer == .answered) gpa.free(answer.answered);
        if (landingFor(answer)) |landing| return .{ .land = landing };
        return .{ .none = .nobody_answered };
    }
    if (!approval.hasTerminal(io)) return .{ .none = .nobody_answered };

    const stdin = approval.Stdin{};
    const console = stdin.console();
    console.write(io, landing_question);

    var buffer: [approval.max_answer_bytes]u8 = undefined;
    const said = switch (console.read(io, &buffer, @intCast(chock_broker.Broker.default_timeout_ms))) {
        .bytes => |count| buffer[0..count],
        .idle, .ended, .canceled => {
            console.write(io, "\n");
            return .{ .none = .nobody_answered };
        },
    };
    if (chock_policy.apply.Mode.fromAnswer(said)) |landing| return .{ .land = landing };
    return .{ .none = .nobody_answered };
}

/// `given` is what the driver of this build declares it applies. Every layer is
/// in it on Linux; Darwin declares four, and neither a system call filter nor a
/// mounted workspace. A layer that failed to apply never reaches this, because
/// the Linux driver refuses rather than degrades. `witness` is the one thing this
/// machine can answer differently, and it only ever takes a layer away.
fn sandboxLayers(
    given: sandbox.Sandbox.Guarantees,
    witness: LayerWitness,
    network: sandbox.namespace.Network,
    workspace: []const u8,
) [layer_names.len]ui.Layer {
    std.debug.assert(witness.unavailable.subsetOf(witness.probed));

    var built: [layer_names.len]ui.Layer = undefined;
    for (layer_names, &built) |named, *slot| {
        const note: []const u8 = switch (named.guarantee) {
            .network_isolated => switch (network) {
                .none => "none",
                .filtered => "filtered",
                .host => "host",
            },
            .workspace_mounted => workspace,
            else => "",
        };
        const state: ui.Layer.State = if (!given.contains(named.guarantee))
            .unsupported
        else if (witness.unavailable.contains(named.guarantee))
            .unavailable
        else if (named.guarantee == .network_isolated and network == .host)
            .off
        else
            .on;
        slot.* = .{ .name = named.name, .note = note, .state = state };
    }
    return built;
}

/// Two sets and not one, so a refusal can be told from a question nobody asked.
/// `unavailable` is always a subset of `probed`. A guarantee in neither reads
/// on, because the driver applies it and dies if it cannot.
const LayerWitness = struct {
    probed: sandbox.Sandbox.Guarantees = sandbox.Sandbox.Guarantees.initEmpty(),
    unavailable: sandbox.Sandbox.Guarantees = sandbox.Sandbox.Guarantees.initEmpty(),

    fn saw(self: *LayerWitness, guarantee: sandbox.Sandbox.Guarantee, available: bool) void {
        self.probed.insert(guarantee);
        if (!available) self.unavailable.insert(guarantee);
    }
};

/// A layer this build applies is enforced or the call dies, so a probe cannot
/// make its tick truer. What a probe can find is a machine that refuses the layer
/// outright. `path_restricted` reads the Landlock ABI version and changes
/// nothing. The three namespace guarantees come from one fork that calls
/// `namespace.enter`. `syscall_restricted` forks a child that installs this
/// build's filter, because a filter cannot be removed. `workspace_mounted` is not
/// probed: the namespace probe builds no root and pivots into none. Linux only.
fn witnessLayers(
    gpa: std.mem.Allocator,
    given: sandbox.Sandbox.Guarantees,
) LayerWitness {
    var out = LayerWitness{};
    if (builtin.target.os.tag != .linux) return out;

    if (given.contains(.path_restricted)) {
        if (sandbox.landlock.probeAbi()) |_| {
            out.saw(.path_restricted, true);
        } else |_| {
            out.saw(.path_restricted, false);
        }
    }

    const namespaces = sandbox.namespace.probeAvailability();
    if (namespaces != .unknown) {
        for ([_]sandbox.Sandbox.Guarantee{
            .signal_isolated,
            .ipc_isolated,
            .network_isolated,
        }) |guarantee| {
            if (given.contains(guarantee)) out.saw(guarantee, namespaces.available());
        }
    }

    if (given.contains(.syscall_restricted)) {
        // Built here and not in the child: a fork may happen while another thread
        // holds this allocator's lock. No trap set: a filter that asks for a user
        // notification with no listener behind it makes the kernel answer every
        // observed call with `ENOSYS`.
        if (sandbox.seccomp.build(gpa, .{})) |insns| {
            defer gpa.free(insns);
            switch (sandbox.seccomp.probeInstall(sandbox.bpf.Prog.init(insns))) {
                .ok => out.saw(.syscall_restricted, true),
                .refused => out.saw(.syscall_restricted, false),
                .unknown => {},
            }
        } else |_| {}
    }

    return out;
}

const layer_names = [_]struct {
    name: []const u8,
    guarantee: sandbox.Sandbox.Guarantee,
}{
    .{ .name = "net", .guarantee = .network_isolated },
    .{ .name = "fs", .guarantee = .workspace_mounted },
    .{ .name = "pid", .guarantee = .signal_isolated },
    .{ .name = "ipc", .guarantee = .ipc_isolated },
    .{ .name = "seccomp", .guarantee = .syscall_restricted },
    .{ .name = "landlock", .guarantee = .path_restricted },
};

comptime {
    var seen = sandbox.Sandbox.Guarantees.initEmpty();
    for (layer_names) |named| {
        if (seen.contains(named.guarantee)) @compileError(
            "chock run: two header layers name the same sandbox guarantee",
        );
        seen.insert(named.guarantee);
    }
    if (seen.count() != @typeInfo(sandbox.Sandbox.Guarantee).@"enum".fields.len) @compileError(
        "chock run: a sandbox guarantee has no layer in the header",
    );
}

/// Never both a display and the bare prompt: two readers on one descriptor race
/// for every byte, and a prompt written around a display lands in cells the
/// display believes it owns.
fn asksHere(has_display: bool, at_terminal: bool) enum { display, terminal, nobody } {
    if (has_display) return .display;
    if (at_terminal) return .terminal;
    return .nobody;
}

const Approvers = struct {
    stdin: approval.Stdin,
    terminal: approval.Terminal,
    display: approval.Display,
    socket: chock_broker.socket.Waiter,
    pair: chock_broker.socket.Pair,
    at_terminal: bool,
    has_display: bool,
    has_socket: bool,
    attached: usize,

    fn init(
        self: *Approvers,
        gpa: std.mem.Allocator,
        io: std.Io,
        started: *Started,
        locked: *ApprovalLock,
        screen: ?*ui.Ui,
    ) void {
        self.at_terminal = approval.hasTerminal(io);
        self.stdin = .{};
        self.terminal = .{
            .gpa = gpa,
            .storage = started.storage,
            .locked = locked,
            .console = self.stdin.console(),
        };

        self.has_display = screen != null;
        if (screen) |one| {
            self.display = .{
                .gpa = gpa,
                .storage = started.storage,
                .locked = locked,
                .screen = one,
            };
        }

        self.has_socket = started.approvals != null;
        self.attached = 0;
        if (started.approvals) |endpoint| {
            endpoint.acceptPending(io);
            self.attached = endpoint.attached();
            self.socket = .{
                .gpa = gpa,
                .storage = started.storage,
                .locked = locked,
                .endpoint = endpoint,
                .stop = interrupt.requested,
            };
        }
    }

    fn waiter(self: *Approvers) chock_broker.Broker.Waiter {
        const here: ?chock_broker.Broker.Waiter = switch (asksHere(self.has_display, self.at_terminal)) {
            .display => self.display.waiter(),
            .terminal => self.terminal.waiter(),
            .nobody => null,
        };

        if (here) |one| {
            if (!self.has_socket) return one;
            self.pair = .{ .first = one, .second = self.socket.waiter() };
            return self.pair.waiter();
        }
        if (self.has_socket) return self.socket.waiter();
        return chock_broker.Broker.SystemWaiter.waiter();
    }

    fn timeoutMs(self: *const Approvers) i64 {
        return chock_broker.socket.timeoutMs(self.at_terminal or self.has_display, self.attached);
    }

    fn failed(self: *const Approvers) ?anyerror {
        if (self.has_display) {
            if (self.display.failed) |err| return err;
        }
        if (self.terminal.failed) |err| return err;
        if (self.has_socket) {
            if (self.socket.failed) |err| return err;
        }
        return null;
    }
};

const QuestionConsole = struct {
    stdin: approval.Stdin = .{},

    fn console(self: *QuestionConsole) chock_core.ask.Console {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.ask.Console.VTable{ .write = writeFn, .read = readFn };

    fn writeFn(ptr: *anyopaque, io: std.Io, bytes: []const u8) void {
        const self: *QuestionConsole = @ptrCast(@alignCast(ptr));
        self.stdin.console().write(io, bytes);
    }

    fn readFn(
        ptr: *anyopaque,
        io: std.Io,
        buffer: []u8,
        budget_ms: u64,
    ) chock_core.ask.Console.Read {
        const self: *QuestionConsole = @ptrCast(@alignCast(ptr));
        // No `else`: a way for a read to end that `src/approval.zig` adds and
        // this forgets fails the build rather than becoming a silent `idle`.
        return switch (self.stdin.console().read(io, buffer, budget_ms)) {
            .idle => .idle,
            .bytes => |count| .{ .bytes = count },
            .ended => .ended,
            .canceled => .canceled,
        };
    }
};

/// `src/ui.zig` reads its keyboard and repaints in one place, and that place runs
/// only when an event arrives, so between two events nothing reads the keyboard.
/// Built in place and never copied: both seams hold a pointer into this.
const DisplayPump = struct {
    screen: *ui.Ui,

    fn coreIdle(self: *DisplayPump) chock_core.idle.Idle {
        return .{ .ptr = self, .vtable = &core_vtable };
    }

    fn providerIdle(self: *DisplayPump) chock_provider.Client.Idle {
        return .{ .ptr = self, .vtable = &provider_vtable };
    }

    const core_vtable = chock_core.idle.Idle.VTable{ .step = stepFn };
    const provider_vtable = chock_provider.Client.Idle.VTable{ .step = stepFn };

    fn stepFn(ptr: *anyopaque) void {
        const self: *DisplayPump = @ptrCast(@alignCast(ptr));
        self.screen.pumpStep();
    }
};

/// This is not the arbiter and never becomes one. An ask grants nothing,
/// whatever the person types, and appends nothing to the log at all. Built in
/// place and never copied: an `Asker` holds a pointer into this.
const DisplayAsker = struct {
    screen: *ui.Ui,
    stop: *const fn () bool = interrupt.requested,
    timeout_ms: i64 = chock_core.ask.default_timeout_ms,
    now: *const fn (io: std.Io) i64 = nowMs,
    agent_kind: []const u8 = "",

    fn asker(self: *DisplayAsker) chock_core.ask.Asker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.ask.Asker.VTable{ .ask = askFn };

    fn askFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: chock_core.ask.Question,
    ) chock_core.ask.Error!chock_core.ask.Answer {
        const self: *DisplayAsker = @ptrCast(@alignCast(ptr));
        return self.ask(gpa, io, question);
    }

    pub fn ask(
        self: *DisplayAsker,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: chock_core.ask.Question,
    ) chock_core.ask.Error!chock_core.ask.Answer {
        if (self.stop()) return .stopped;

        self.screen.showQuestion(.{
            .agent_kind = self.agent_kind,
            .text = question.text,
            .options = question.options,
            .left_ms = self.timeout_ms,
        });
        defer self.screen.clearQuestion();

        const deadline = self.now(io) + self.timeout_ms;
        while (true) {
            if (self.stop()) return .stopped;

            const left = deadline - self.now(io);
            if (left <= 0) return .timed_out;
            self.screen.questionLeft(left);

            const budget: u64 = @min(
                @as(u64, @intCast(left)),
                chock_core.ask.poll_interval_ms,
            );
            switch (self.screen.awaitText(budget)) {
                .waiting => continue,
                .canceled => return .stopped,
                .declined => return .declined,
                .answered => |said| {
                    const words = chock_core.ask.chosen(said, question.options) orelse said;
                    return .{ .answered = try gpa.dupe(u8, words) };
                },
            }
        }
    }

    fn nowMs(io: std.Io) i64 {
        return std.Io.Timestamp.now(io, .real).toMilliseconds();
    }
};

const ApprovalLock = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// `decide` is handed the loop's own `locked` handle and passes it to
/// `Broker.request`, so there is no second open of the log and no second lock.
/// `foldSessionSince` resumes each question's fold from where the last one
/// stopped: a full replay per question is quadratic in the length of the session,
/// and `gateToolCall` asks for every ordinary tool call. A session that cannot
/// start a reviewer gets `review_unavailable`, which does not permit.
const SessionArbiter = struct {
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *Started,
    options: Options,
    screen: ?*ui.Ui = null,
    /// Kept after the first question and only ever caught up, never rebuilt.
    /// `PolicyFold` and not `state.Session`: a `Session` carries `context`, the
    /// mirrored message history, which grows for the life of the run and which
    /// nothing below ever reads.
    folded: ?chock_proto.state.PolicyFold = null,
    folded_at: u64 = 0,

    fn arbiter(self: *SessionArbiter) chock_core.arbiter.Arbiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn deinit(self: *SessionArbiter) void {
        if (self.folded) |*session| session.deinit();
    }

    const vtable = chock_core.arbiter.Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *chock_core.arbiter.Locked,
        ask: chock_core.arbiter.Ask,
    ) chock_core.arbiter.Answer {
        const self: *SessionArbiter = @ptrCast(@alignCast(ptr));

        if (self.folded == null) self.folded = chock_proto.state.PolicyFold.init(self.gpa);
        const session = &self.folded.?;
        foldSessionSince(gpa, io, self.started.storage, session, &self.folded_at);

        var review_child = reviewChild(self.gpa, self.environ, self.env, self.started, self.options);
        var review_spawner = reviewerFor(review_child.spawner(), self.started, session);

        review_spawner.locked = locked;

        var approvers: Approvers = undefined;
        approvers.init(gpa, io, self.started, locked, self.screen);

        const broker = chock_broker.Broker{
            .policy = self.started.policy,
            .waiter = approvers.waiter(),
            .reviewer = review_spawner.reviewer(),
            .redaction = self.started.redact_values,
            // `session` was just caught up, so it holds every
            // `approved_by_user_for_session` answer given earlier and a person
            // is not asked twice. `session.grants` is filled through that
            // arena, so a live grant has to grow through it too.
            .grants = .{ .memory = &session.grants, .allocator = session.arena.allocator() },
        };

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const promised = promisesFor(
            gpa,
            arena,
            io,
            self.started.paths.dir,
            self.options.parent_session,
            session,
        ) catch &.{};

        var broker_diag: ?chock_broker.Diagnostic = null;
        defer if (broker_diag) |*d| d.deinit(session.arena.allocator());
        // `session.arena.allocator()` and not `gpa`.
        // `chock_proto.state.SessionGrants.granted` is a
        // `std.StringHashMapUnmanaged`, so its `grow` frees the old backing
        // array with whatever allocator the current call passes.
        // `foldSessionSince` filled `session.grants` through this arena, and
        // a regrow past the map's first capacity would otherwise free arena
        // memory through the wrong allocator.
        const outcome = broker.request(session.arena.allocator(), io, self.started.storage, locked, .{
            .action = ask.action,
            .summary = ask.summary,
            .detail = ask.detail,
            .reason = ask.reason,
            .agent_kind = self.options.agent_kind,
            .model_alias = self.started.model_alias,
            .tool = ask.tool,
            .tool_call_id = ask.tool_call_id,
            .source = ask.source,
            .spawn_chain = self.started.spawn_chain,
            .self_policy = promised,
            .timeout_ms = approvers.timeoutMs(),
        }, &broker_diag) catch |err| {
            if (broker_diag) |*fault| {
                tty.print(
                    .warn,
                    "chock: the request for {s} could not be decided: {f}\n",
                    .{ ask.action, fault },
                );
                return .{ .permitted = false, .outcome = "the question could not be put to anybody" };
            }
            tty.print(
                .warn,
                "chock: the request for {s} could not be decided: {t}\n",
                .{ ask.action, err },
            );
            return .{ .permitted = false, .outcome = "the question could not be put to anybody" };
        };

        if (approvers.failed()) |err| {
            tty.print(
                .warn,
                "chock: the approval of {s} could not be shown or recorded: {t}\n",
                .{ ask.action, err },
            );
        }

        return .{
            .permitted = outcome.permits(),
            .outcome = @tagName(outcome),
            .review_text = if (outcome.reviewOutcome()) |review|
                chock_broker.review.requesterText(review)
            else
                "",
        };
    }
};

/// One of these for the whole session. A dispatch runs to completion before the
/// next one starts unless it asked to run in the background, and a background
/// call is kept away from this seam, so renaming `network.tool` once per call is
/// safe. `network.asker` starts null and `giveFn` fills it exactly once, after
/// `Loop.run` takes the handle; until then an `ask` decision refuses outright.
/// The fold is caught up before every call and resumed from a kept offset,
/// because a mid session `restrict_self` is invisible to a stale copy.
const ToolNetwork = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    started: *Started,
    screen: ?*ui.Ui,

    network: chock_broker.network.Network,
    transport: chock_broker.network.System = .{},
    background_nets: [chock_core.tasks.max_tasks]BackgroundNet = @splat(.{}),
    background_used: usize = 0,
    approval_wait_ns: std.atomic.Value(u64) = .init(0),

    session: chock_proto.state.PolicyFold,
    folded_at: u64 = 0,
    approvers: Approvers = undefined,
    broker: chock_broker.Broker = undefined,

    fn seam(self: *ToolNetwork) chock_core.tools.NetSeam {
        return .{ .ptr = self, .vtable = &seam_vtable };
    }

    const seam_vtable = chock_core.tools.NetSeam.VTable{
        .router = routerFn,
        .background_router = backgroundRouterFn,
    };

    /// One network per background call, because that call reads it on a thread of
    /// its own long after this returns and `self.network` is rewritten by the
    /// next foreground call.
    const BackgroundNet = struct {
        network: chock_broker.network.Network = undefined,
        id: [64]u8 = undefined,
        id_len: usize = 0,
    };

    /// `asker` is left null on purpose. A `Network` with no asker answers `allow`
    /// from the table and refuses everything else outright, so a background call
    /// reaches what the policy permits and never reaches for the session loop's
    /// locked handle.
    fn backgroundRouterFn(ptr: *anyopaque, tool: []const u8, call_id: []const u8) ?sandbox.NetRouter {
        const self: *ToolNetwork = @ptrCast(@alignCast(ptr));
        if (!self.started.policy.wantsBackgroundRouter()) return null;
        if (self.background_used == self.background_nets.len) return null;

        self.network.self_policy = refreshToolPromises(self.gpa, self.io, self.started.storage, &self.session, &self.folded_at);

        const slot = &self.background_nets[self.background_used];
        self.background_used += 1;

        slot.id_len = @min(call_id.len, slot.id.len);
        @memcpy(slot.id[0..slot.id_len], call_id[0..slot.id_len]);

        slot.network = self.network;
        slot.network.asker = null;
        slot.network.tool = tool;
        slot.network.tool_call_id = slot.id[0..slot.id_len];
        slot.network.granted = 0;
        slot.network.refused = 0;
        slot.network.diagnostic = null;
        return slot.network.netRouter();
    }

    fn routerFn(ptr: *anyopaque, tool: []const u8, call_id: []const u8) sandbox.NetRouter {
        const self: *ToolNetwork = @ptrCast(@alignCast(ptr));
        self.network.tool = tool;
        self.network.tool_call_id = call_id;
        self.approval_wait_ns.store(0, .monotonic);
        self.network.self_policy = refreshToolPromises(self.gpa, self.io, self.started.storage, &self.session, &self.folded_at);
        return self.network.netRouter();
    }

    fn giveFn(self: *ToolNetwork, locked: *chock_core.arbiter.Locked) void {
        self.network.self_policy = refreshToolPromises(self.gpa, self.io, self.started.storage, &self.session, &self.folded_at);
        self.approvers.init(self.gpa, self.io, self.started, locked, self.screen);
        self.broker = .{
            .policy = self.started.policy,
            .waiter = self.approvers.waiter(),
            .redaction = self.started.redact_values,
            // `self.session.grants` is filled through `self.session.arena`, and
            // `chock_broker.network.zig` calls `asker.broker.request` with a
            // plain allocator, so a `grants_allocator` left unset here lets a
            // `grow` free arena memory through that plain allocator.
            .grants = .{ .memory = &self.session.grants, .allocator = self.session.arena.allocator() },
        };
        self.network.asker = .{
            .broker = &self.broker,
            .storage = self.started.storage,
            .locked = locked,
            .approval_wait_ns = &self.approval_wait_ns,
        };
    }

    fn deinit(self: *ToolNetwork) void {
        if (self.network.refused != 0) {
            tty.print(
                .warn,
                "chock: a tool call's own network was refused {d} of {d} connections it asked for.\n",
                .{ self.network.refused, self.network.refused + self.network.granted },
            );
            if (self.network.diagnostic) |*one| tty.print(.warn, "chock: the first was {f}\n", .{one});
        } else if (self.network.granted != 0) {
            tty.print(
                .dim,
                "chock: a tool call's own network reached {d} connection{s}.\n",
                .{ self.network.granted, if (self.network.granted == 1) "" else "s" },
            );
        }
        self.logSummary();
        if (self.network.diagnostic) |*one| one.deinit(self.gpa);
        self.session.deinit();
    }

    fn logSummary(self: *ToolNetwork) void {
        var diag_text: ?[]u8 = null;
        defer if (diag_text) |t| self.gpa.free(t);
        if (self.network.diagnostic) |*one| {
            diag_text = std.fmt.allocPrint(self.gpa, "{f}", .{one}) catch null;
        }
        logNetworkSummary(
            self.gpa,
            self.io,
            self.started.storage,
            self.network.granted,
            self.network.refused,
            diag_text orelse "",
        );
    }
};

/// Hands the session's own locked handle to every party that asks a question from
/// inside a turn. All of them run inside the turn `Loop.run` holds the log's
/// exclusive lock for, so none may open the log a second time. A session whose
/// asker is null runs no third party tool at all.
const GiveLockedToAll = struct {
    network: *ToolNetwork,
    mcp: *chock_core.mcp.Session,
    plugins: *chock_core.plugin.Session,
    git: *GitToolRunner,
    nix: *NixBuildToolRunner,

    fn giveLocked(self: *GiveLockedToAll) chock_core.Loop.GiveLocked {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.GiveLocked.VTable{ .give = giveFn };

    fn giveFn(ptr: *anyopaque, locked: *chock_core.arbiter.Locked) void {
        const self: *GiveLockedToAll = @ptrCast(@alignCast(ptr));
        ToolNetwork.giveFn(self.network, locked);
        giveLockedToAskers(self.mcp, self.plugins, self.git, self.nix, locked);
    }
};

fn giveLockedToAskers(
    mcp_session: *chock_core.mcp.Session,
    plugin_session: *chock_core.plugin.Session,
    git_runner: *GitToolRunner,
    nix_runner: *NixBuildToolRunner,
    locked: *chock_core.arbiter.Locked,
) void {
    mcp_session.giveLocked(locked);
    plugin_session.giveLocked(locked);
    git_runner.giveLocked(locked);
    nix_runner.giveLocked(locked);
}

fn logNetworkSummary(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    granted: usize,
    refused: usize,
    diagnostic_text: []const u8,
) void {
    const ev = networkSummaryEvent(granted, refused, diagnostic_text) orelse return;

    var locked = storage.lock(io) catch |err| {
        tty.print(
            .warn,
            "chock: a tool call's own network summary could not be written to the log: {s}\n",
            .{@errorName(err)},
        );
        return;
    };
    defer locked.unlock(io) catch {};
    _ = locked.append(
        gpa,
        io,
        ev,
        std.Io.Timestamp.now(io, .real).toMilliseconds(),
    ) catch |err| {
        tty.print(
            .warn,
            "chock: a tool call's own network summary could not be written to the log: {s}\n",
            .{@errorName(err)},
        );
    };
}

/// Always, and not only when something degraded. A reader that finds no event
/// cannot tell a session where every supervisor confined itself from a session
/// written by a build that did not know the fact. Walking
/// `sandbox.Sandbox.failModeFor` keeps the log and the driver naming the same
/// three layers.
fn logSupervisorAudit(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    audit: *const sandbox.Sandbox.SupervisorAudit,
) void {
    var locked = storage.lock(io) catch |err| {
        reportSupervisorRecord(err);
        return;
    };
    defer locked.unlock(io) catch {};
    inline for (comptime std.enums.values(sandbox.Sandbox.LayerName)) |layer| {
        if (comptime sandbox.Sandbox.failModeFor(.supervisor, layer)) |mode| {
            _ = locked.append(
                gpa,
                io,
                supervisorEvent(layer, mode, audit.counts(layer)),
                std.Io.Timestamp.now(io, .real).toMilliseconds(),
            ) catch |err| reportSupervisorRecord(err);
        }
    }
}

fn reportSupervisorRecord(err: anyerror) void {
    tty.print(
        .warn,
        "chock: whether the process that holds the credential could confine itself " ++
            "could not be written to the log: {s}\n",
        .{@errorName(err)},
    );
}

fn supervisorEvent(
    layer: sandbox.Sandbox.LayerName,
    fail_mode: sandbox.Sandbox.FailMode,
    counts: sandbox.Sandbox.SupervisorAudit.Counts,
) chock_proto.event.Event {
    return .{
        .sandbox_supervisor = .{
            .process = sandbox.Sandbox.SupervisorAudit.process_name,
            .layer = layer.wireName(),
            .fail_mode = @tagName(fail_mode),
            .confined = counts.confined,
            .unconfined = counts.unconfined,
            .unreported = counts.unreported,
            .reason = if (counts.first_fault) |fault| @tagName(fault) else "",
        },
    };
}

fn logSyscallAudit(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    audit: *sandbox.Sandbox.SyscallAudit,
) void {
    var rows: [syscall_row_count]chock_proto.event.SyscallCount = undefined;
    var path_rows: [syscall_row_count]chock_proto.event.UnverifiedPaths = undefined;
    var names: [syscall_name_cap][]const u8 = undefined;
    const ev = syscallEvent(
        audit.counts(),
        audit.pathCounts(),
        &rows,
        &path_rows,
        &names,
    );

    var locked = storage.lock(io) catch |err| {
        reportSyscallRecord(err);
        return;
    };
    defer locked.unlock(io) catch {};
    _ = locked.append(
        gpa,
        io,
        ev,
        std.Io.Timestamp.now(io, .real).toMilliseconds(),
    ) catch |err| reportSyscallRecord(err);
}

fn reportSyscallRecord(err: anyerror) void {
    tty.print(
        .warn,
        "chock: what the sandboxed programs of this session asked the kernel for " ++
            "could not be written to the log: {s}\n",
        .{@errorName(err)},
    );
}

const syscall_row_count = @typeInfo(sandbox.seccomp.TrapCall).@"enum".fields.len;

const syscall_name_cap = sandbox.Sandbox.SyscallAudit.name_cap;

fn syscallEvent(
    counts: sandbox.Sandbox.SyscallAudit.Counts,
    paths: sandbox.Sandbox.SyscallAudit.PathCounts,
    rows: *[syscall_row_count]chock_proto.event.SyscallCount,
    path_rows: *[syscall_row_count]chock_proto.event.UnverifiedPaths,
    names: *[syscall_name_cap][]const u8,
) chock_proto.event.Event {
    var filled: usize = 0;
    inline for (@typeInfo(sandbox.seccomp.TrapCall).@"enum".fields) |field| {
        const first = filled;
        var kept: u32 = 0;
        while (kept < paths.kept) : (kept += 1) {
            if (paths.name_call[kept] != field.value) continue;
            if (filled >= names.len) break;
            names[filled] = paths.names[kept];
            filled += 1;
        }
        rows[field.value] = .{ .name = field.name, .count = counts.calls[field.value] };
        path_rows[field.value] = .{
            .granted = paths.granted[field.value],
            .ungranted = paths.ungranted[field.value],
            .ungranted_unnamed = paths.ungranted_unnamed[field.value],
            .relative = paths.relative[field.value],
            .unread = paths.unread[field.value],
            .truncated = paths.truncated[field.value],
            .ungranted_names = names[first..filled],
        };
        const row = path_rows[field.value];
        const said_something = row.granted != 0 or row.ungranted != 0 or
            row.ungranted_unnamed != 0 or row.relative != 0 or row.unread != 0 or
            row.truncated != 0 or row.ungranted_names.len != 0;
        if (said_something) rows[field.value].unverified_paths = row;
    }
    return .{
        .sandbox_syscalls = .{
            .mechanism = sandbox.Sandbox.SyscallAudit.mechanism_name,
            .observed = counts.observed,
            .unobserved = counts.unobserved,
            .calls = rows,
            // False: the supervisor lets the held call run, so the program can change
            // the argument after the reader read it.
            .paths_verified = false,
            .path_readers_unreported = paths.readers_unreported,
            .path_readers_absent = paths.readers_absent,
        },
    };
}

fn networkSummaryEvent(
    granted: usize,
    refused: usize,
    diagnostic_text: []const u8,
) ?chock_proto.event.Event {
    if (granted == 0 and refused == 0) return null;
    return .{ .network_summary = .{
        .granted = @intCast(granted),
        .refused = @intCast(refused),
        .diagnostic = diagnostic_text,
    } };
}

test "the supervisor event names the fault, and the audit question is one field" {
    const ev = supervisorEvent(.seccomp, .open, .{
        .confined = 11,
        .unconfined = 2,
        .unreported = 1,
        .first_fault = .no_new_privs_refused,
    });
    try std.testing.expectEqual(chock_proto.event.Kind.sandbox_supervisor, std.meta.activeTag(ev));
    try std.testing.expectEqualStrings("supervisor", ev.sandbox_supervisor.process);
    try std.testing.expectEqualStrings("seccomp", ev.sandbox_supervisor.layer);
    try std.testing.expectEqual(@as(u64, 11), ev.sandbox_supervisor.confined);
    try std.testing.expectEqual(@as(u64, 2), ev.sandbox_supervisor.unconfined);
    try std.testing.expectEqual(@as(u64, 1), ev.sandbox_supervisor.unreported);
    try std.testing.expectEqualStrings("no_new_privs_refused", ev.sandbox_supervisor.reason);
}

test "the event says which way the layer fails, and the answer comes from the sandbox table" {
    const table = sandbox.Sandbox.failModeFor(.supervisor, .seccomp).?;
    try std.testing.expectEqual(sandbox.Sandbox.FailMode.open, table);
    const open = supervisorEvent(.seccomp, table, .{
        .confined = 1,
        .unconfined = 0,
        .unreported = 0,
        .first_fault = null,
    });
    try std.testing.expectEqualStrings("open", open.sandbox_supervisor.fail_mode);

    const closed = supervisorEvent(.seccomp, .closed, .{
        .confined = 1,
        .unconfined = 0,
        .unreported = 0,
        .first_fault = null,
    });
    try std.testing.expectEqualStrings("closed", closed.sandbox_supervisor.fail_mode);

    for (comptime std.enums.values(sandbox.Sandbox.LayerName)) |layer| {
        try std.testing.expectEqual(
            @as(?sandbox.Sandbox.FailMode, .closed),
            sandbox.Sandbox.failModeFor(.sandboxed, layer),
        );
    }
}

test "every layer the supervisor puts on itself gets a row of its own" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01SUPERVISORLAYERS00000000");
    const storage = backing.storage();
    defer storage.close(io);

    var audit: sandbox.Sandbox.SupervisorAudit = .{};
    audit.record(.capabilities, .on);
    audit.record(.landlock, .{ .off = .rejected });
    audit.record(.seccomp, .on);
    logSupervisorAudit(gpa, io, storage, &audit);

    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var rows: usize = 0;
    var landlock_unconfined: u64 = 0;
    var seccomp_unconfined: u64 = 1;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .sandbox_supervisor) continue;
        rows += 1;
        const said = parsed.value.event.sandbox_supervisor;
        try std.testing.expectEqualStrings("open", said.fail_mode);
        if (std.mem.eql(u8, said.layer, "landlock")) landlock_unconfined = said.unconfined;
        if (std.mem.eql(u8, said.layer, "seccomp")) seccomp_unconfined = said.unconfined;
    }
    try std.testing.expectEqual(@as(usize, 3), rows);
    try std.testing.expectEqual(@as(u64, 1), landlock_unconfined);
    try std.testing.expectEqual(@as(u64, 0), seccomp_unconfined);
}

test "a session where every supervisor confined itself still writes the event" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01SUPERVISORCLEAN000000000");
    const storage = backing.storage();
    defer storage.close(io);

    var audit: sandbox.Sandbox.SupervisorAudit = .{};
    audit.record(.seccomp, .on);
    audit.record(.seccomp, .on);
    logSupervisorAudit(gpa, io, storage, &audit);

    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var found = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .sandbox_supervisor) continue;
        if (!std.mem.eql(u8, parsed.value.event.sandbox_supervisor.layer, "seccomp")) continue;
        found = true;
        const said = parsed.value.event.sandbox_supervisor;
        try std.testing.expectEqual(@as(u64, 2), said.confined);
        try std.testing.expectEqual(@as(u64, 0), said.unconfined);
        try std.testing.expectEqualStrings("", said.reason);
    }
    try std.testing.expect(found);
}

test "the supervisor's own degradation reaches the log, not only the terminal" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01SUPERVISOR00000000000000");
    const storage = backing.storage();
    defer storage.close(io);

    var audit: sandbox.Sandbox.SupervisorAudit = .{};
    audit.record(.seccomp, .on);
    audit.record(.seccomp, .{ .off = .not_permitted });
    logSupervisorAudit(gpa, io, storage, &audit);

    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var found = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .sandbox_supervisor) continue;
        if (!std.mem.eql(u8, parsed.value.event.sandbox_supervisor.layer, "seccomp")) continue;
        found = true;
        const said = parsed.value.event.sandbox_supervisor;
        try std.testing.expectEqual(@as(u64, 1), said.confined);
        try std.testing.expectEqual(@as(u64, 1), said.unconfined);
        try std.testing.expectEqualStrings("seccomp", said.layer);
        try std.testing.expectEqualStrings("not_permitted", said.reason);
    }
    try std.testing.expect(found);
}

test "the syscall event names one row for each call the sandbox can watch, and says nothing was watched" {
    var rows: [syscall_row_count]chock_proto.event.SyscallCount = undefined;
    var path_rows: [syscall_row_count]chock_proto.event.UnverifiedPaths = undefined;
    var names: [syscall_name_cap][]const u8 = undefined;
    const ev = syscallEvent(.{
        .observed = 4,
        .unobserved = 1,
        .calls = .{ 900, 4, 0, 12 },
    }, emptyPathCounts(), &rows, &path_rows, &names);

    try std.testing.expectEqual(chock_proto.event.Kind.sandbox_syscalls, std.meta.activeTag(ev));
    const said = ev.sandbox_syscalls;
    try std.testing.expectEqualStrings("seccomp_user_notif", said.mechanism);
    try std.testing.expectEqual(@as(u64, 4), said.observed);
    try std.testing.expectEqual(@as(u64, 1), said.unobserved);
    try std.testing.expectEqual(syscall_row_count, said.calls.len);

    inline for (@typeInfo(sandbox.seccomp.TrapCall).@"enum".fields) |field| {
        try std.testing.expectEqualStrings(field.name, said.calls[field.value].name);
    }
    try std.testing.expectEqual(
        @as(u64, 900),
        said.calls[@intFromEnum(sandbox.seccomp.TrapCall.openat)].count,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        said.calls[@intFromEnum(sandbox.seccomp.TrapCall.connect)].count,
    );
    try std.testing.expectEqual(
        @as(?chock_proto.event.UnverifiedPaths, null),
        said.calls[@intFromEnum(sandbox.seccomp.TrapCall.openat)].unverified_paths,
    );
    try std.testing.expectEqual(false, said.paths_verified);
    try std.testing.expectEqual(@as(u64, 0), said.path_readers_unreported);
}

test "a full path record is still one short line of the session log" {
    const gpa = std.testing.allocator;
    var longest: [sandbox.notify.kept_path_bytes]u8 = @splat('n');
    longest[0] = '/';

    var counted = emptyPathCounts();
    counted.kept = syscall_name_cap;
    for (0..syscall_name_cap) |slot| {
        counted.name_call[slot] = @intFromEnum(sandbox.seccomp.TrapCall.openat);
        counted.names[slot] = &longest;
    }
    for (0..sandbox.notify.call_count) |slot| {
        counted.granted[slot] = std.math.maxInt(u32);
        counted.ungranted[slot] = std.math.maxInt(u32);
        counted.ungranted_unnamed[slot] = std.math.maxInt(u32);
        counted.relative[slot] = std.math.maxInt(u32);
        counted.unread[slot] = std.math.maxInt(u32);
        counted.truncated[slot] = std.math.maxInt(u32);
    }

    var rows: [syscall_row_count]chock_proto.event.SyscallCount = undefined;
    var path_rows: [syscall_row_count]chock_proto.event.UnverifiedPaths = undefined;
    var names: [syscall_name_cap][]const u8 = undefined;
    const ev = syscallEvent(.{
        .observed = 1000,
        .unobserved = 0,
        .calls = @splat(std.math.maxInt(u32)),
    }, counted, &rows, &path_rows, &names);

    const line = try chock_proto.event.toJson(gpa, .{
        .id = 0,
        .session = "01JQ0000000000000000000000",
        .time_ms = 1_700_000_000_000,
        .event = ev,
    });
    defer gpa.free(line);

    try std.testing.expect(line.len < 2048);
}

fn emptyPathCounts() sandbox.Sandbox.SyscallAudit.PathCounts {
    return .{
        .readers_unreported = 0,
        .readers_absent = 0,
        .granted = sandbox.notify.empty_counts,
        .ungranted = sandbox.notify.empty_counts,
        .ungranted_unnamed = sandbox.notify.empty_counts,
        .relative = sandbox.notify.empty_counts,
        .unread = sandbox.notify.empty_counts,
        .truncated = sandbox.notify.empty_counts,
        .kept = 0,
        .name_call = @splat(0),
        .names = @splat(&.{}),
    };
}

test "the syscall event names each call's own paths, and says they are not verified" {
    const openat = @intFromEnum(sandbox.seccomp.TrapCall.openat);
    const execve = @intFromEnum(sandbox.seccomp.TrapCall.execve);

    var counted = emptyPathCounts();
    counted.readers_unreported = 2;
    counted.readers_absent = 1;
    counted.granted[openat] = 812;
    counted.ungranted[openat] = 9;
    counted.ungranted_unnamed[openat] = 6;
    counted.relative[openat] = 71;
    counted.truncated[openat] = 1;
    counted.ungranted[execve] = 1;
    counted.kept = 3;
    counted.name_call[0] = openat;
    counted.names[0] = "/etc/passwd";
    counted.name_call[1] = execve;
    counted.names[1] = "/bin/sh";
    counted.name_call[2] = openat;
    counted.names[2] = "/home/someone/.ssh/id_ed25519";

    var rows: [syscall_row_count]chock_proto.event.SyscallCount = undefined;
    var path_rows: [syscall_row_count]chock_proto.event.UnverifiedPaths = undefined;
    var names: [syscall_name_cap][]const u8 = undefined;
    const ev = syscallEvent(.{
        .observed = 1,
        .unobserved = 0,
        .calls = .{ 821, 1, 0, 0 },
    }, counted, &rows, &path_rows, &names);

    const said = ev.sandbox_syscalls;
    try std.testing.expectEqual(false, said.paths_verified);
    try std.testing.expectEqual(@as(u64, 2), said.path_readers_unreported);
    try std.testing.expectEqual(@as(u64, 1), said.path_readers_absent);

    const opens = said.calls[openat].unverified_paths.?;
    try std.testing.expectEqual(@as(u64, 812), opens.granted);
    try std.testing.expectEqual(@as(u64, 9), opens.ungranted);
    try std.testing.expectEqual(@as(u64, 6), opens.ungranted_unnamed);
    try std.testing.expectEqual(@as(u64, 71), opens.relative);
    try std.testing.expectEqual(@as(u64, 1), opens.truncated);
    try std.testing.expectEqual(@as(usize, 2), opens.ungranted_names.len);
    try std.testing.expectEqualStrings("/etc/passwd", opens.ungranted_names[0]);
    try std.testing.expectEqualStrings("/home/someone/.ssh/id_ed25519", opens.ungranted_names[1]);

    const execs = said.calls[execve].unverified_paths.?;
    try std.testing.expectEqual(@as(usize, 1), execs.ungranted_names.len);
    try std.testing.expectEqualStrings("/bin/sh", execs.ungranted_names[0]);

    try std.testing.expectEqual(
        @as(?chock_proto.event.UnverifiedPaths, null),
        said.calls[@intFromEnum(sandbox.seccomp.TrapCall.connect)].unverified_paths,
    );
}

test "what the sandboxed programs asked the kernel for reaches the log, not only the counter" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01SYSCALLS0000000000000000");
    const storage = backing.storage();
    defer storage.close(io);

    var audit: sandbox.Sandbox.SyscallAudit = .{};
    var counts = sandbox.notify.empty_counts;
    counts[@intFromEnum(sandbox.seccomp.TrapCall.openat)] = 31;
    counts[@intFromEnum(sandbox.seccomp.TrapCall.execve)] = 1;
    audit.record(.{ .observed = counts });
    audit.record(.unobserved);
    logSyscallAudit(gpa, io, storage, &audit);

    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var found = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .sandbox_syscalls) continue;
        found = true;
        const said = parsed.value.event.sandbox_syscalls;
        try std.testing.expectEqual(@as(u64, 1), said.observed);
        try std.testing.expectEqual(@as(u64, 1), said.unobserved);
        try std.testing.expectEqualStrings("seccomp_user_notif", said.mechanism);
        for (said.calls) |row| {
            if (std.mem.eql(u8, row.name, "openat")) {
                try std.testing.expectEqual(@as(u64, 31), row.count);
            }
        }
    }
    try std.testing.expect(found);
}

test "a session that watched nothing still writes the event, so an absence is never an answer" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01SYSCALLSQUIET00000000000");
    const storage = backing.storage();
    defer storage.close(io);

    var audit: sandbox.Sandbox.SyscallAudit = .{};
    logSyscallAudit(gpa, io, storage, &audit);

    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var found = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .sandbox_syscalls) continue;
        found = true;
        const said = parsed.value.event.sandbox_syscalls;
        try std.testing.expectEqual(@as(u64, 0), said.observed);
        try std.testing.expectEqual(@as(u64, 0), said.unobserved);
        try std.testing.expectEqual(syscall_row_count, said.calls.len);
    }
    try std.testing.expect(found);
}

test "a session with no network use writes no summary at all" {
    try std.testing.expectEqual(@as(?chock_proto.event.Event, null), networkSummaryEvent(0, 0, ""));
}

test "a session's own network summary carries what the terminal line said, for the log this time" {
    const ev = networkSummaryEvent(3, 1, "the host did not resolve") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(chock_proto.event.Kind.network_summary, std.meta.activeTag(ev));
    try std.testing.expectEqual(@as(u64, 3), ev.network_summary.granted);
    try std.testing.expectEqual(@as(u64, 1), ev.network_summary.refused);
    try std.testing.expectEqualStrings("the host did not resolve", ev.network_summary.diagnostic);
}

test "a tool call's own network reaches the log, not only the terminal" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETSUMMARY0000000000000");
    const storage = backing.storage();
    defer storage.close(io);

    logNetworkSummary(gpa, io, storage, 4, 1, "the host did not resolve");

    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var found = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .network_summary) continue;
        found = true;
        try std.testing.expectEqual(@as(u64, 4), parsed.value.event.network_summary.granted);
        try std.testing.expectEqual(@as(u64, 1), parsed.value.event.network_summary.refused);
        try std.testing.expectEqualStrings(
            "the host did not resolve",
            parsed.value.event.network_summary.diagnostic,
        );
    }
    try std.testing.expect(found);
}

test "a session with nothing granted and nothing refused writes no summary to the log either" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETSUMMARYNONE00000000000");
    const storage = backing.storage();
    defer storage.close(io);

    logNetworkSummary(gpa, io, storage, 0, 0, "");

    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try std.testing.expect(parsed.value.event != .network_summary);
    }
}

fn refreshToolPromises(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    session: *chock_proto.state.PolicyFold,
    at: *u64,
) []const chock_policy.ratchet.Restriction {
    foldSessionSince(gpa, io, storage, session, at);
    return chock_core.self_policy.restrictionsFrom(
        session.arena.allocator(),
        session.self_policy.restrictions.items,
    ) catch &.{};
}

test "a mid session restrict_self reaches refreshToolPromises on the very next call, and a fold-once cache does not see it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01TOOLPROMISE");
    const storage = backing.storage();
    defer storage.close(io);

    const action = "net.connect";

    var stale = chock_proto.state.Session.init(gpa);
    defer stale.deinit();
    foldSession(gpa, io, storage, &stale);
    const stale_promised = chock_core.self_policy.restrictionsFrom(
        stale.arena.allocator(),
        stale.self_policy.restrictions.items,
    ) catch &.{};
    try std.testing.expectEqual(@as(usize, 0), stale_promised.len);

    var live = chock_proto.state.PolicyFold.init(gpa);
    defer live.deinit();
    var live_at: u64 = 0;
    const first = refreshToolPromises(gpa, io, storage, &live, &live_at);
    try std.testing.expectEqual(@as(usize, 0), first.len);

    var locked = try storage.lock(io);
    _ = try locked.append(gpa, io, .{ .policy_self = .{
        .restrictions = &.{.{ .action = action, .ceiling = .deny, .reason = "narrowed mid session" }},
        .authorised = false,
    } }, 0);
    try locked.unlock(io);

    try std.testing.expectEqual(@as(usize, 0), stale.self_policy.restrictions.items.len);

    const second = refreshToolPromises(gpa, io, storage, &live, &live_at);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqualStrings(action, second[0].action);
    try std.testing.expectEqual(chock_policy.table.Decision.deny, second[0].ceiling);
}

const SessionHandback = struct {
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *Started,
    options: Options,
    screen: ?*ui.Ui = null,

    fn handback(self: *SessionHandback) chock_core.handback.Handback {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.handback.Handback.VTable{ .apply = applyFn };

    fn applyFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *chock_core.handback.Locked,
        ask: chock_core.handback.Ask,
    ) std.mem.Allocator.Error!chock_core.handback.Result {
        _ = io;
        const self: *SessionHandback = @ptrCast(@alignCast(ptr));

        // An `Io` of its own: phase 2 runs over `Allocator.failing`, so
        // `Threaded.spawnPosix` fails there and every step below runs `git`.
        // Backed by the page allocator, because a background task's thread
        // may be inside `Sandbox.spawn` and a lock another thread holds at a
        // `fork` is one the child inherits as held for ever.
        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = self.environ });
        defer threaded.deinit();
        const spawning_io = threaded.io();

        const tree = switch (self.started.workspace.kind) {
            .worktree => |wt| wt,
            .overlay => return .{ .carried = false, .output = try gpa.dupe(
                u8,
                "nothing was carried back and nobody was asked: this session works on a copy of " ++
                    "the project rather than on a git worktree of it, so there is no commit to " ++
                    "carry and no ref to move. Say in your answer what you changed and where.",
            ) },
        };

        const moved = tree.headMoved(gpa, spawning_io, self.env, null) catch |err| {
            return .{ .carried = false, .output = try std.fmt.allocPrint(
                gpa,
                "nothing was carried back and nobody was asked: whether you have made a commit " ++
                    "could not be read ({s}). Say in your answer that the work is not carried " ++
                    "back.",
                .{@errorName(err)},
            ) };
        };
        const new_id = moved orelse return .{
            .carried = false,
            .output = try self.nothingCommitted(gpa, spawning_io, tree),
        };
        defer gpa.free(new_id);

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const ref = try applyRef(arena, self.started.session_id);
        var carried = carryCommit(gpa, arena, spawning_io, .{
            .environ = self.environ,
            .env = self.env,
            .started = self.started,
            .options = self.options,
            .locked = locked,
            .screen = self.screen,
            .tree = tree,
            .new_id = new_id,
            .ref = ref,
            .reason = ask.reason,
            .tool_call_id = ask.tool_call_id,
        });
        defer carried.deinit(gpa);

        return switch (carried) {
            .already_there => .{ .carried = true, .output = try std.fmt.allocPrint(
                gpa,
                "already carried back: the ref {s} in {s} is at this very commit, so nothing " ++
                    "moved and nobody was asked again. The user reads it with `git log {s}`.",
                .{ ref, tree.project_root, ref },
            ) },
            .not_described => .{ .carried = false, .output = try gpa.dupe(
                u8,
                "nothing was carried back and nobody was asked: what your commit would change " ++
                    "could not be read, so there was nothing to put in front of anybody. Say in " ++
                    "your answer that the work is not carried back.",
            ) },
            .failed => .{ .carried = false, .output = try gpa.dupe(
                u8,
                "the request was allowed and carrying the work out failed. Your commit may not " ++
                    "be in the user's repository. Say so in your answer, and do not commit the " ++
                    "same work again.",
            ) },
            .refused => |outcome| .{ .carried = false, .output = try std.fmt.allocPrint(
                gpa,
                "nothing was carried back: the answer was \"{s}\". The user's repository is " ++
                    "unchanged and your commit is still in this workspace. That is not a " ++
                    "judgement of the work. Say in your answer what you did and that it was not " ++
                    "carried back.{s}",
                .{ @tagName(outcome), reviewNote(outcome) },
            ) },
            .landed => |done| switch (done.integration) {
                .moved => |m| .{ .carried = true, .output = try std.fmt.allocPrint(
                    gpa,
                    "carried back: {d} objects and the ref {s} are now in {s}, and this project " ++
                        "asks for {s}, so **their branch {s} moved to {s}** and their working " ++
                        "tree is at it. Say in your answer that the work is on their branch.",
                    .{ done.objects, ref, tree.project_root, m.landing.wireName(), m.branch, m.to },
                ) },
                .park => |p| parked: {
                    const note = if (p.wanted) |it|
                        try std.fmt.allocPrint(
                            gpa,
                            " The {s} this apply would have taken did not happen, because {s}.",
                            .{ it.wireName(), p.why.sentence() },
                        )
                    else
                        try std.fmt.allocPrint(
                            gpa,
                            " No branch moved, because {s}.",
                            .{p.why.sentence()},
                        );
                    defer gpa.free(note);
                    break :parked .{ .carried = true, .output = try std.fmt.allocPrint(
                        gpa,
                        "carried back: {d} objects and the ref {s} are now in {s}. The user " ++
                            "reads it with `git log {s}` and takes it with `git merge {s}`. " ++
                            "**No branch of theirs moved.**{s} Say in your answer that the work " ++
                            "is on that ref and waiting for them.",
                        .{ done.objects, ref, tree.project_root, ref, ref, note },
                    ) };
                },
            },
        };
    }

    fn nothingCommitted(
        self: *SessionHandback,
        gpa: std.mem.Allocator,
        io: std.Io,
        tree: chock_workspace.worktree.Worktree,
    ) std.mem.Allocator.Error![]u8 {
        const counts = chock_workspace.worktree.countUncommitted(
            gpa,
            io,
            self.env,
            tree.path,
            null,
        ) catch |err| return std.fmt.allocPrint(
            gpa,
            "nothing was carried back and nobody was asked: you have made no commit, and what " ++
                "is left in the workspace could not be counted ({s}). Only a commit is carried " ++
                "back. Commit your work and ask again.",
            .{@errorName(err)},
        );

        if (!counts.any()) return gpa.dupe(
            u8,
            "nothing was carried back and nobody was asked: you have made no commit and no file " ++
                "in the workspace is changed, so there is nothing to carry. If you meant to " ++
                "change something, you have not yet.",
        );

        return std.fmt.allocPrint(
            gpa,
            "nothing was carried back and nobody was asked: you have changed {d} files ({d} " ++
                "modified, {d} new) and made no commit. Only a commit is carried back, and the " ++
                "workspace you are in is thrown away when the session ends. Commit the work and " ++
                "call this again.",
            .{ counts.total(), counts.modified, counts.untracked },
        );
    }
};

fn reviewNote(outcome: chock_broker.Broker.Outcome) []const u8 {
    const review = outcome.reviewOutcome() orelse return "";
    return chock_broker.review.requesterText(review);
}

/// Carry the session's own commit back into the user's repository, through the
/// broker, after an approval. The worktree is thrown away at the end of the run,
/// so without this the agent's work has no path back at all. Nothing here widens
/// what the sandbox can do: the act runs in this process, on the host, with the
/// agent already gone.
fn applyWork(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *Started,
    options: Options,
) !Applied {
    const tree = switch (started.workspace.kind) {
        .worktree => |wt| wt,
        .overlay => return .nothing_to_apply,
    };

    const new_id = try tree.headMoved(gpa, io, env, null) orelse return uncommittedWork(gpa, io, env, tree);
    defer gpa.free(new_id);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ref = try applyRef(arena, started.session_id);

    var locked = try started.storage.lock(io);
    defer locked.unlock(io) catch {};

    var carried = carryCommit(gpa, arena, io, .{
        .environ = environ,
        .env = env,
        .started = started,
        .options = options,
        .locked = &locked,
        .screen = null,
        .tree = tree,
        .new_id = new_id,
        .ref = ref,
        .reason = "the session made a commit, and the workspace it is in is about to be removed",
        .tool_call_id = "",
    });
    defer carried.deinit(gpa);

    switch (carried) {
        .not_described, .failed => return .failed,
        .already_there => {
            tty.print(
                .plain,
                "chock run: the ref {s} is already at the session's commit {s} in {s}, " ++
                    "so nothing was carried and nobody was asked again.\n" ++
                    "chock run: read it with `git log {s}`, and take it with " ++
                    "`git merge {s}`.\n",
                .{ ref, new_id, tree.project_root, ref, ref },
            );
            return .landed;
        },
        .refused => |outcome| {
            tty.print(
                .warn,
                "chock run: the session's commit {s} was not applied ({s}). " ++
                    "Your repository is unchanged.\n",
                .{ new_id, @tagName(outcome) },
            );
            if (outcome.reviewOutcome() != null) {
                tty.print(
                    .warn,
                    "chock run: a reviewer agent decided this. The verdict and its reason are in " ++
                        "the approval.response of {s}.\n",
                    .{started.paths.log},
                );
            }
            return .refused;
        },
        .landed => |done| {
            tty.print(
                .plain,
                "chock run: {d} objects and the ref {s} were applied to {s}.\n",
                .{ done.objects, ref, tree.project_root },
            );
            switch (done.integration) {
                .moved => |m| tty.print(
                    .plain,
                    "chock run: your branch {s} moved from {s} to {s} ({s}), and your working " ++
                        "tree is there now.\n" ++
                        "chock run: put it back with `git reset --hard {s}`.\n",
                    .{ m.branch, shortId(m.from), shortId(m.to), m.landing.wireName(), m.from },
                ),
                .park => |p| {
                    if (p.wanted) |it| tty.print(
                        .warn,
                        "chock run: the {s} this apply would have taken did not happen, " ++
                            "because {s}. No branch of yours moved.\n",
                        .{ it.wireName(), p.why.sentence() },
                    ) else tty.print(
                        .plain,
                        "chock run: no branch of yours moved, because {s}.\n",
                        .{p.why.sentence()},
                    );
                    tty.print(
                        .plain,
                        "chock run: read it with `git log {s}`, and take it with " ++
                            "`git merge {s}`.\n",
                        .{ ref, ref },
                    );
                },
            }
            return .landed;
        },
    }
}

const CarryOut = union(enum) {
    not_described,
    already_there,
    refused: chock_broker.Broker.Outcome,
    /// This one owns memory. The branch names and the two object ids come out of
    /// the broker's own `Result` and are handed on rather than copied, so nothing
    /// here can fail for want of memory once the work has landed.
    landed: struct {
        objects: usize,
        integration: chock_broker.integrate.Outcome,
    },

    failed,

    fn deinit(self: *CarryOut, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .landed => |*done| done.integration.deinit(gpa),
            .not_described, .already_there, .refused, .failed => {},
        }
        self.* = undefined;
    }
};

/// Ask for one `workspace.apply` and carry it out when the answer permits it. An
/// agent that asks gains nothing an agent that waits would not have had, and in
/// particular it cannot move a branch. It takes the lock and never opens the log,
/// so it works both mid session and at the end of one.
fn carryCommit(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    params: struct {
        environ: std.process.Environ,
        env: *std.process.Environ.Map,
        started: *Started,
        options: Options,
        locked: *ApprovalLock,
        screen: ?*ui.Ui,
        tree: chock_workspace.worktree.Worktree,
        new_id: []const u8,
        ref: []const u8,
        reason: []const u8,
        tool_call_id: []const u8,
    },
) CarryOut {
    const started = params.started;
    const ctx = chock_broker.actions.Context{ .env = params.env };
    var describe_diag: ?chock_broker.Diagnostic = null;
    defer if (describe_diag) |*d| d.deinit(arena);
    const wanted = chosenLanding(gpa, io, started.apply_mode.mode, params.screen);
    const copies = copiesOf(arena, &started.workspace) catch return .failed;
    const apply = chock_broker.actions.WorkspaceApply.describing(arena, io, ctx, .{
        .repository = params.tree.project_root,
        .scratch_object_store = params.tree.object_store_source,
        .ref = params.ref,
        .new_id = params.new_id,
        .wanted = wanted,
        .copies = copies,
    }, &describe_diag) catch |err| {
        if (describe_diag) |*fault| {
            tty.print(
                .err,
                "chock run: what the session's work would change could not be read: {f}\n",
                .{fault},
            );
        } else {
            tty.print(
                .err,
                "chock run: what the session's work would change could not be read: {s}\n",
                .{@errorName(err)},
            );
        }
        return .not_described;
    };
    if (describe_diag) |*notice| tty.print(.warn, "chock run: {f}\n", .{notice});

    // Before anybody is asked: a compare and swap from an id to itself moves
    // nothing. The branch has to have nothing to gain either, because a mode that
    // integrates can leave the branch untouched when the working tree was dirty
    // at the moment of the first request.
    if (std.mem.eql(u8, apply.old_id, apply.new_id) and apply.integration == .park) {
        recordIntegration(gpa, io, params.locked, started.apply_mode, params.ref, .{
            .park = .{ .wanted = wanted.landing(), .why = .already_there },
        });
        return .already_there;
    }

    var session = chock_proto.state.Session.init(gpa);
    defer session.deinit();
    foldSession(gpa, io, started.storage, &session);

    const promised = promisesFor(
        gpa,
        arena,
        io,
        started.paths.dir,
        params.options.parent_session,
        &session,
    ) catch return .failed;

    var review_child = reviewChild(gpa, params.environ, params.env, started, params.options);
    var review_spawner = reviewerFor(review_child.spawner(), started, &session);

    review_spawner.locked = params.locked;

    var approvers: Approvers = undefined;
    approvers.init(gpa, io, started, params.locked, params.screen);

    const broker = chock_broker.Broker{
        .policy = started.policy,
        .waiter = approvers.waiter(),
        .reviewer = review_spawner.reviewer(),
        .redaction = started.redact_values,
        // `session` holds every `approved_by_user_for_session` answer already
        // given, so a person keeps the rest of the session they were offered. The
        // arena and not `gpa`: `gpa` frees the `Result` after `session` is gone,
        // so growing `session.grants` through it would free arena memory through
        // the wrong allocator.
        .grants = .{ .memory = &session.grants, .allocator = session.arena.allocator() },
    };

    var apply_diag: ?chock_broker.Diagnostic = null;
    defer if (apply_diag) |*d| d.deinit(gpa);
    var attempt = chock_broker.actions.run(&broker, gpa, io, started.storage, params.locked, ctx, .{
        .action = .{ .workspace_apply = apply },
        .reason = params.reason,
        .agent_kind = params.options.agent_kind,
        .spawn_chain = started.spawn_chain,
        .model_alias = started.model_alias,
        .tool = chock_broker.actions.self_asked_tool,
        .tool_call_id = params.tool_call_id,
        .self_policy = promised,
        .timeout_ms = approvers.timeoutMs(),
    }, &apply_diag) catch |err| {
        if (apply_diag) |*fault| {
            tty.print(.err, "chock run: the session's work could not be applied: {f}\n", .{fault});
        } else {
            tty.print(
                .err,
                "chock run: the session's work could not be applied: {s}\n",
                .{@errorName(err)},
            );
        }
        return .failed;
    };

    if (approvers.failed()) |err| {
        tty.print(
            .warn,
            "chock run: the approval of the session's work could not be shown or recorded: {t}\n",
            .{err},
        );
    }

    switch (attempt) {
        .refused => |outcome| {
            recordIntegration(gpa, io, params.locked, started.apply_mode, params.ref, .{
                .park = .{ .wanted = wanted.landing(), .why = .apply_refused },
            });
            return .{ .refused = outcome };
        },
        .done => |*done| {
            const carried = done.result.workspace_apply;
            writeBackCopies(gpa, io, &started.workspace);
            recordIntegration(gpa, io, params.locked, started.apply_mode, params.ref, carried.integration);
            gpa.free(carried.ref);
            gpa.free(carried.new_id);
            return .{ .landed = .{
                .objects = carried.objects_moved,
                .integration = carried.integration,
            } };
        },
    }
}

/// The `workspace` block's copies which land on the user's own files when the
/// session's work applies. The prompt names them, so the answer to it is the
/// answer to these too.
fn copiesOf(
    arena: std.mem.Allocator,
    workspace: *const chock_workspace.Workspace,
) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (workspace.binds) |one| {
        if (one.bind.mode != .copy or !one.bind.write_back) continue;
        try out.append(arena, one.bind.relative);
    }
    return out.toOwnedSlice(arena);
}

/// After the apply is permitted and never before it. A refused apply leaves
/// the user's files untouched and the session's copies in the workspace.
fn writeBackCopies(
    gpa: std.mem.Allocator,
    io: std.Io,
    workspace: *const chock_workspace.Workspace,
) void {
    var report = chock_workspace.worktree.ImportReport{};
    defer report.deinit(gpa);
    const done = workspace.writeBackBinds(gpa, io, &report) catch |err| {
        tty.print(.warn, "chock run: the workspace copies could not be written back: {t}\n", .{err});
        return;
    };
    for (report.skipped.items) |skip| {
        tty.print(.warn, "chock run: {s} was not written back: {s}\n", .{ skip.path, skip.reason });
    }
    if (done.binds == 0) return;
    tty.print(.plain, "chock run: {d} files written back over your own, from {d} binds.\n", .{
        done.files,
        done.binds,
    });
}

fn recordIntegration(
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: *ApprovalLock,
    apply_mode: ApplyMode,
    ref: []const u8,
    outcome: chock_broker.integrate.Outcome,
) void {
    const moved = switch (outcome) {
        .moved => |m| m,
        .park => null,
    };
    _ = locked.append(gpa, io, .{
        .workspace_integrate = .{
            .ref = ref,
            .mode = switch (outcome) {
                .moved => |m| m.landing.wireName(),
                .park => |p| if (p.wanted) |it| it.wireName() else "",
            },
            .decision = @tagName(apply_mode.decision),
            .branch = if (moved) |m| m.branch else "",
            .branch_from = if (moved) |m| m.from else "",
            .branch_to = if (moved) |m| m.to else "",
            .parked = switch (outcome) {
                .moved => "",
                .park => |p| p.why.wireName(),
            },
        },
    }, std.Io.Timestamp.now(io, .real).toMilliseconds()) catch |err| {
        tty.print(
            .warn,
            "chock run: what this apply did to your branch could not be written to the log: {s}\n",
            .{@errorName(err)},
        );
    };
}

/// An agent that can write leaves files behind and `git worktree remove` deletes
/// them, so saying nothing is a run that exits 0 with the project unchanged and
/// the work gone.
fn uncommittedWork(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *std.process.Environ.Map,
    tree: chock_workspace.worktree.Worktree,
) Applied {
    const counts = chock_workspace.worktree.countUncommitted(gpa, io, env, tree.path, null) catch |err| {
        tty.print(
            .err,
            "chock run: the session made no commit, and the work left in {s} could not be counted: {s}\n",
            .{ tree.path, @errorName(err) },
        );
        return .nothing_to_apply;
    };
    if (!counts.any()) return .nothing_to_apply;

    tty.print(
        .warn,
        "chock run: the agent changed {d} files ({d} modified, {d} new) and made no commit, " ++
            "so there is nothing to carry back.\n" ++
            "chock run: only a commit reaches your project. Your repository is unchanged, and " ++
            "the work itself is kept: see the workspace named below.\n",
        .{ counts.total(), counts.modified, counts.untracked },
    );
    return .uncommitted;
}

/// `git worktree add` checks out the commit and not the working tree, so an agent
/// in a fresh worktree sees `HEAD` and a user who is not told believes it can see
/// work it cannot. The overlay kind of workspace copies the whole project
/// directory, so nothing there is invisible. Returns how many files the agent
/// will not see, which is zero in every case where nothing is hidden.
fn handleUncommitted(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *std.process.Environ.Map,
    workspace: *const chock_workspace.Workspace,
    options: Options,
) StartError!usize {
    const tree = switch (workspace.kind) {
        .worktree => |wt| wt,
        .overlay => return 0,
    };

    if (!options.allow_dirty) {
        const counts = chock_workspace.worktree.countUncommitted(gpa, io, env, tree.project_root, null) catch |err| {
            tty.print(
                .warn,
                "chock run: the uncommitted work in {s} could not be counted: {s}. " ++
                    "The agent sees the committed state.\n",
                .{ tree.project_root, @errorName(err) },
            );
            return 0;
        };
        if (!counts.any()) return 0;
        const text = try dirtyWarning(gpa, counts);
        defer gpa.free(text);
        tty.print(.warn, "{s}", .{text});
        return counts.total();
    }

    var import_diag: ?chock_workspace.Diagnostic = null;
    var report = tree.importUncommitted(gpa, io, env, &import_diag) catch |err| {
        if (import_diag) |*fault| {
            tty.print(
                .err,
                "chock run: the uncommitted work in {s} could not be copied in: {f}\n",
                .{ tree.project_root, fault },
            );
            return error.Reported;
        }
        tty.print(
            .err,
            "chock run: the uncommitted work in {s} could not be copied in: {s}\n",
            .{ tree.project_root, @errorName(err) },
        );
        return error.Reported;
    };
    defer report.deinit(gpa);

    if (report.total() == 0 and report.skipped.items.len == 0) {
        tty.print(.plain, "chock run: there was no uncommitted work to bring across.\n", .{});
        return 0;
    }
    const text = try importSentence(gpa, report);
    defer gpa.free(text);
    tty.print(.plain, "{s}", .{text});
    for (report.skipped.items) |skip| {
        tty.print(.warn, "chock run: {s} was not brought across: {s}\n", .{ skip.path, skip.reason });
    }
    return 0;
}

fn dirtyWarning(
    gpa: std.mem.Allocator,
    counts: chock_workspace.worktree.Uncommitted,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "chock run: {d} uncommitted files will not be visible to the agent\n" ++
            "           ({d} modified, {d} untracked). Pass --allow-dirty to include them.\n",
        .{ counts.total(), counts.modified, counts.untracked },
    );
}

fn importSentence(
    gpa: std.mem.Allocator,
    report: chock_workspace.worktree.ImportReport,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "chock run: {d} files brought across from your working tree " ++
            "({d} modified, {d} new, {d} removed).\n",
        .{
            report.total(),
            report.modified.items.len,
            report.added.items.len,
            report.deleted.items.len,
        },
    );
}

fn warnUnmeasurableBudget(
    budget: ?chock_cost.budget.Budget,
    billing: chock_cost.prices.Billing,
    provider_name: []const u8,
    model: []const u8,
) void {
    const cap = budget orelse return;
    if (billing == .free) return;
    if (chock_cost.prices.lookup(model) != null) return;
    tty.print(
        .warn,
        "chock: the budget of {d:.2} {s} cannot be enforced: no price is known for model {s} " ++
            "on provider {s}, and an unknown cost is not a zero. The session runs anyway.\n",
        .{ cap.max_cost, cap.currency, model, provider_name },
    );
}
/// Well above a forge token and far below `chock_core.ask.max_answer_bytes`. A
/// person who types more is refused plainly rather than given a value cut in
/// half, because half a password is a wrong password.
const max_secret_bytes: usize = 512;

const secret_prompt_timeout_ms: i64 = 180_000;

const secret_look_ms: u64 = 100;

/// A terminal and the display, and never the approval socket. The unix path of
/// that socket checks `peercred` and the TCP path checks nobody, so a password
/// crossing it would be a password on the wire. A session with neither refuses
/// the push.
const SecretAsker = struct {
    io: std.Io,
    screen: ?*ui.Ui = null,
    at_terminal: bool = false,

    fn canAsk(self: SecretAsker) bool {
        return self.screen != null or self.at_terminal;
    }

    const nobody_text = "this session cannot prompt anybody for a password: a credential is typed " ++
        "at the terminal running chock, or into the display's own question region, and this " ++
        "session has neither. It is never asked for over the approval socket, because chock " ++
        "does no authentication on that socket. Push from a session you are sitting at, or use " ++
        "an ssh remote, whose key never leaves your machine.";

    fn ask(self: SecretAsker, question: []const u8, into: []u8) ?[]const u8 {
        if (self.screen) |screen| return askDisplay(screen, self.io, question, into);
        if (!self.at_terminal) return null;
        return tty.readSecret(self.io, question, into) catch null;
    }

    fn askDisplay(screen: *ui.Ui, io: std.Io, question: []const u8, into: []u8) ?[]const u8 {
        screen.showQuestion(.{ .text = question, .echo = .masked });
        defer screen.clearQuestion();

        const started_ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
        const deadline_ms = started_ms + secret_prompt_timeout_ms;
        while (true) {
            const now_ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
            if (now_ms >= deadline_ms) return null;
            screen.questionLeft(deadline_ms - now_ms);
            switch (screen.awaitText(secret_look_ms)) {
                .waiting => continue,
                .canceled, .declined => return null,
                .answered => |said| {
                    if (said.len == 0 or said.len > into.len) return null;
                    @memcpy(into[0..said.len], said);
                    return into[0..said.len];
                },
            }
        }
    }
};

/// What one approved `git push` may reach, and nothing else may. `arm` opens what
/// the push needs, `disarm` closes it, and `grantFn` answers null for every call
/// but the one between them. A proxied ssh agent can sign anything at all while
/// it is reachable and the agent protocol cannot say what a signature is for, so
/// scope is the only defence there is. The value is typed by a person, held for
/// one tool call, and overwritten in `disarm`.
const GitCredentials = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// Not the session's `.ctl` directory, which is bound into no sandbox
    /// ever: an agent that could reach the approval socket could answer its
    /// own questions.
    dir: []const u8,
    helper: []const u8,
    secrets: SecretAsker,
    asker: chock_broker.askpass.Asker,
    host_agent: []const u8,
    live: ?*chock_core.redact.Secret = null,

    armed_call: ?[]const u8 = null,
    socket_path: []u8 = &.{},
    agent_path: []u8 = &.{},
    env: []const []const u8 = &.{},
    endpoint: ?chock_broker.askpass.Endpoint = null,
    proxy: ?chock_broker.agentproxy.Proxy = null,

    host: [chock_broker.askpass.max_host_bytes]u8 = undefined,
    host_len: usize = 0,
    secret: [max_secret_bytes]u8 = undefined,
    secret_len: usize = 0,
    grant: [1]chock_broker.askpass.Grant = undefined,

    const Outcome = union(enum) {
        ready,
        refused: []u8,
    };

    fn seam(self: *GitCredentials) chock_core.credentials.Seam {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.credentials.Seam.VTable{ .grant = grantFn, .step = stepFn };

    fn grantFn(ptr: *anyopaque, tool: []const u8, call_id: []const u8) ?chock_core.credentials.Grant {
        const self: *GitCredentials = @ptrCast(@alignCast(ptr));
        const armed = self.armed_call orelse return null;
        if (!std.mem.eql(u8, armed, call_id)) return null;
        // The tool is checked as well as the call, so a grant cannot travel
        // to a different tool that happened to be given the same id.
        if (!std.mem.eql(u8, tool, "run_command")) return null;

        return .{
            .host_dir = self.dir,
            .helper_source = if (self.endpoint != null and self.helper.len != 0) self.helper else null,
            .helper_name = chock_broker.askpass.link_name,
            .env = self.env,
        };
    }

    fn stepFn(ptr: *anyopaque) void {
        const self: *GitCredentials = @ptrCast(@alignCast(ptr));
        if (self.endpoint) |*one| _ = one.step(self.gpa, self.io, null, self.asker, step_budget_ms) catch {};
        if (self.proxy) |*one| one.step(self.io, step_budget_ms);
    }

    const step_budget_ms = 20;

    fn arm(
        self: *GitCredentials,
        gpa: std.mem.Allocator,
        io: std.Io,
        project_root: []const u8,
        call_id: []const u8,
        rest: []const []const u8,
    ) std.mem.Allocator.Error!Outcome {
        std.debug.assert(self.armed_call == null);

        const resolved = self.remoteUrl(gpa, io, project_root, rest) catch null;
        defer if (resolved) |url| gpa.free(url);

        const url = resolved orelse return .{ .refused = try gpa.dupe(u8, unreadable_remote_text) };

        switch (chock_broker.git_remote.credentialFor(url)) {
            .none => return .ready,
            .unreadable => return .{ .refused = try gpa.dupe(u8, unreadable_remote_text) },
            .password => return self.armPassword(gpa, io, call_id, url),
            .agent => return self.armAgent(gpa, io, call_id, url),
        }
    }

    fn remoteUrl(
        self: *GitCredentials,
        gpa: std.mem.Allocator,
        io: std.Io,
        project_root: []const u8,
        rest: []const []const u8,
    ) !?[]u8 {
        _ = self;
        const named = chock_broker.git_remote.remoteNameIn(rest) orelse return null;
        if (chock_broker.git_remote.namesAUrl(named)) return try gpa.dupe(u8, named);

        const path = try projectConfigPath(gpa, project_root);
        defer gpa.free(path);

        const text = std.Io.Dir.readFileAlloc(
            .cwd(),
            io,
            path,
            gpa,
            .limited(chock_broker.git_remote.max_config_bytes),
        ) catch return null;
        defer gpa.free(text);

        const url = chock_broker.git_remote.remoteUrlIn(text, named) orelse return null;
        return try gpa.dupe(u8, url);
    }

    fn armPassword(
        self: *GitCredentials,
        gpa: std.mem.Allocator,
        io: std.Io,
        call_id: []const u8,
        url: []const u8,
    ) std.mem.Allocator.Error!Outcome {
        const host = chock_broker.git_remote.hostIn(url) orelse
            return .{ .refused = try gpa.dupe(u8, unreadable_remote_text) };
        if (!isPlainHost(host)) return .{ .refused = try gpa.dupe(u8, unreadable_remote_text) };

        if (self.asker.mayPrompt(host)) |refusal| {
            return .{ .refused = try std.fmt.allocPrint(
                gpa,
                "git push was not run: {s}",
                .{refusal.text()},
            ) };
        }

        if (!self.secrets.canAsk()) {
            return .{ .refused = try gpa.dupe(u8, SecretAsker.nobody_text) };
        }
        if (self.helper.len == 0) {
            return .{ .refused = try gpa.dupe(u8, no_helper_text) };
        }

        const question = try std.fmt.allocPrint(
            gpa,
            "password for {s} (git push, nothing is stored): ",
            .{host},
        );
        defer gpa.free(question);

        const typed = self.secrets.ask(question, &self.secret) orelse {
            return .{ .refused = try gpa.dupe(u8, nothing_typed_text) };
        };
        self.secret_len = typed.len;
        errdefer self.wipe();

        // Before anything is opened. Nothing can echo the value until the
        // socket exists, so there is no window at all rather than a short one.
        if (self.live) |slot| slot.value = self.secret[0..self.secret_len];

        @memcpy(self.host[0..host.len], host);
        self.host_len = host.len;
        self.grant[0] = .{
            .host = self.host[0..self.host_len],
            .secret = self.secret[0..self.secret_len],
        };
        self.asker.grants = .{ .entries = &self.grant };

        self.socket_path = try std.fmt.allocPrint(
            gpa,
            "{s}/{s}",
            .{ self.dir, chock_broker.askpass.socket_name },
        );
        errdefer {
            gpa.free(self.socket_path);
            self.socket_path = &.{};
        }

        self.endpoint = chock_broker.askpass.Endpoint.open(io, self.socket_path, null) catch {
            return .{ .refused = try gpa.dupe(u8, no_socket_text) };
        };
        errdefer if (self.endpoint) |*one| {
            one.close(io);
            self.endpoint = null;
        };

        const inside = chock_core.credentials.sandboxDirFor(self.dir);
        const helper_inside = try chock_core.credentials.helperPathFor(
            gpa,
            self.helper,
            chock_broker.askpass.link_name,
        );
        defer gpa.free(helper_inside);

        var entries: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (entries.items) |entry| gpa.free(entry);
            entries.deinit(gpa);
        }
        try entries.append(gpa, try std.fmt.allocPrint(gpa, "GIT_ASKPASS={s}", .{helper_inside}));
        try entries.append(gpa, try std.fmt.allocPrint(
            gpa,
            "{s}={s}/{s}",
            .{ chock_broker.askpass.env_socket, inside, chock_broker.askpass.socket_name },
        ));
        // git writes its two prompts through gettext, so a translated git
        // writes bytes `askpass.readPrompt` cannot read and then refuses.
        try entries.append(gpa, try gpa.dupe(u8, "LC_ALL=C"));
        // Nothing may fall back to a terminal: a git that opened /dev/tty
        // inside the sandbox would be asking nobody.
        try entries.append(gpa, try gpa.dupe(u8, "GIT_TERMINAL_PROMPT=0"));
        self.env = try entries.toOwnedSlice(gpa);

        self.armed_call = try gpa.dupe(u8, call_id);
        return .ready;
    }

    fn armAgent(
        self: *GitCredentials,
        gpa: std.mem.Allocator,
        io: std.Io,
        call_id: []const u8,
        url: []const u8,
    ) std.mem.Allocator.Error!Outcome {
        _ = url;
        if (self.host_agent.len == 0) {
            return .{ .refused = try gpa.dupe(u8, no_agent_text) };
        }

        self.agent_path = try std.fmt.allocPrint(
            gpa,
            "{s}/{s}",
            .{ self.dir, chock_broker.agentproxy.socket_name },
        );
        errdefer {
            gpa.free(self.agent_path);
            self.agent_path = &.{};
        }

        self.proxy = chock_broker.agentproxy.Proxy.open(
            io,
            self.agent_path,
            self.host_agent,
            null,
        ) catch {
            return .{ .refused = try gpa.dupe(u8, no_socket_text) };
        };
        errdefer if (self.proxy) |*one| {
            one.close(io);
            self.proxy = null;
        };

        const inside = chock_core.credentials.sandboxDirFor(self.dir);
        var entries: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (entries.items) |entry| gpa.free(entry);
            entries.deinit(gpa);
        }
        try entries.append(gpa, try std.fmt.allocPrint(
            gpa,
            "{s}={s}/{s}",
            .{ chock_broker.agentproxy.env_socket, inside, chock_broker.agentproxy.socket_name },
        ));
        try entries.append(gpa, try gpa.dupe(u8, "GIT_TERMINAL_PROMPT=0"));
        self.env = try entries.toOwnedSlice(gpa);

        self.armed_call = try gpa.dupe(u8, call_id);
        return .ready;
    }

    /// Called on every path out of an approved push, including a failing one,
    /// because the socket existing one moment longer than the act is what
    /// this design guards against.
    fn disarm(self: *GitCredentials, gpa: std.mem.Allocator, io: std.Io) void {
        if (self.endpoint) |*one| one.close(io);
        self.endpoint = null;
        if (self.proxy) |*one| one.close(io);
        self.proxy = null;

        if (self.socket_path.len != 0) gpa.free(self.socket_path);
        self.socket_path = &.{};
        if (self.agent_path.len != 0) gpa.free(self.agent_path);
        self.agent_path = &.{};
        if (self.env.len != 0) chock_core.credentials.freeEnvironment(gpa, self.env);
        self.env = &.{};
        if (self.armed_call) |one| gpa.free(one);
        self.armed_call = null;

        self.wipe();
    }

    fn wipe(self: *GitCredentials) void {
        if (self.live) |slot| slot.value = "";
        chock_broker.askpass.wipe(self.secret[0..self.secret_len]);
        self.secret_len = 0;
        self.host_len = 0;
        self.grant = undefined;
        self.asker.grants = .{};
    }

    /// Write what the sockets did into the session log, after the tool call
    /// has ended: a look runs in the middle of a call the loop has not
    /// returned from and may not append. A prompt's text is bytes `git`
    /// composed out of a URL, and `askpass.appendPrompt` takes no `Grants` at
    /// all.
    fn record(self: *GitCredentials, gpa: std.mem.Allocator, io: std.Io, locked: ?*chock_core.arbiter.Locked) void {
        const endpoint = if (self.endpoint) |*one| one else return;
        const handle = locked orelse return;

        var index: usize = 0;
        while (endpoint.keptPrompt(index)) |prompt| : (index += 1) {
            var id_buffer: [32]u8 = undefined;
            const correlation = std.fmt.bufPrint(&id_buffer, "askpass-{d}", .{index + 1}) catch "askpass";
            _ = chock_broker.askpass.appendPrompt(
                gpa,
                io,
                handle,
                correlation,
                prompt,
                std.Io.Timestamp.now(io, .real).toMilliseconds(),
            ) catch return;
        }
    }
};

/// The project's own `.git`, and never the session workspace's, which is the
/// agent's to write. A linked worktree shares the project's configuration
/// anyway, so this is also the file `git` would really read.
fn projectConfigPath(gpa: std.mem.Allocator, project_root: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}/.git/config", .{project_root});
}

fn isPlainHost(host: []const u8) bool {
    if (host.len == 0 or host.len > chock_broker.askpass.max_host_bytes) return false;
    for (host) |byte| {
        const ok = std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '-';
        if (!ok) return false;
    }
    return true;
}

const unreadable_remote_text = "git push was not run: chock could not read which remote this " ++
    "push goes to, and it will not guess. A credential is armed from the remote's scheme, so a " ++
    "remote it cannot read is one it cannot arm the right thing for. Name the remote's URL on " ++
    "the command line, as in git push https://host/project.git HEAD:main, and run it again.";

const no_agent_text = "git push was not run: this remote authenticates with an ssh key, and " ++
    "there is no ssh agent for chock to proxy. chock never copies a key into the sandbox, so an " ++
    "agent is the only way a key can sign for it. Start one and add the key, as in ssh-add, and " ++
    "run chock again. An https remote is prompted for instead and needs no agent.";

const no_socket_text = "git push was not run: chock could not open the socket the credential " ++
    "travels on. Nothing was sent anywhere. This is a fault on this machine and not a refusal.";

const no_helper_text = "git push was not run: chock could not resolve its own path, so it " ++
    "could not put the password helper inside the sandbox. This is a fault on this machine and " ++
    "not a refusal.";

const credentials_not_wired_text = "git push was not run: this session has no way to hold a " ++
    "credential, so nothing could authenticate. This is a fault in how the session was started " ++
    "and not a refusal. Report it, and work with what is already in the workspace.";

const nothing_typed_text = "git push was not run: chock asked for the password and nobody " ++
    "typed one, so the push was declined. Nothing was sent anywhere. Ask the user whether they " ++
    "want this push to happen at all before trying it again.";

/// A `ToolRunner` that reads a `run_command` call for a git command line before
/// it runs. It prevents a mistake and it is not a boundary: the capability layers
/// stop the same things whether this runner is in the way or not. A subcommand
/// that reaches another host is asked about and still does not run, even
/// approved, because an act that leaves the sandbox needs a payload naming the
/// effect and an argument vector holds no object id, no lease and no remote URL.
const GitToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    asker: ?chock_core.arbiter.Asker = null,
    credentials: ?*GitCredentials = null,
    project_root: []const u8 = "",

    fn runner(self: *GitToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn giveLocked(self: *GitToolRunner, locked: *chock_core.arbiter.Locked) void {
        if (self.asker) |*one| one.locked = locked;
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *GitToolRunner = @ptrCast(@alignCast(ptr));
        defer self.finishPush(gpa, io);

        if (try self.gitAnswer(gpa, io, call)) |output| {
            return .{
                .call_id = try gpa.dupe(u8, call.call_id),
                .output = output,
                .is_error = true,
                .truncated = false,
            };
        }
        return self.inner.dispatch(gpa, io, call);
    }

    fn finishPush(self: *GitToolRunner, gpa: std.mem.Allocator, io: std.Io) void {
        const creds = self.credentials orelse return;
        if (creds.armed_call == null) return;
        creds.record(gpa, io, if (self.asker) |one| one.locked else null);
        creds.disarm(gpa, io);
    }

    fn gitAnswer(
        self: *GitToolRunner,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) std.mem.Allocator.Error!?[]u8 {
        if (!std.mem.eql(u8, call.tool, "run_command")) return null;

        const Args = struct { argv: []const []const u8 };
        const parsed = std.json.parseFromSlice(Args, gpa, call.arguments, .{
            .ignore_unknown_fields = true,
        }) catch return null;
        defer parsed.deinit();

        const argv = parsed.value.argv;
        if (argv.len == 0) return null;
        // `chock_core.tools` refuses any spelling with a slash in it before this
        // runner is reached, so there is one spelling of git to match here.
        if (!std.mem.eql(u8, argv[0], "git")) return null;

        const ask = switch (chock_broker.git_shim.classify(argv)) {
            .run_the_real_git => return null,
            .ask => |a| a,
        };

        const action = try ask.actionName(gpa);
        defer gpa.free(action);
        const summary = try chock_broker.git_shim.summaryOf(gpa, ask);
        defer gpa.free(summary);
        const detail = try chock_broker.git_shim.detailOf(gpa, ask, argv);
        defer gpa.free(detail);

        const answer = chock_core.arbiter.Asker.decide(self.asker, gpa, io, .{
            .action = action,
            .summary = summary,
            .detail = detail,
            .reason = "",
            .tool = call.tool,
            .tool_call_id = call.call_id,
            .source = chock_broker.git_shim.request_source,
        });

        if (!answer.permitted) return try chock_core.arbiter.refusalText(gpa, action, answer);

        if (std.mem.eql(u8, ask.subcommand, "push")) {
            return try self.armPush(gpa, io, call, ask.rest);
        }

        if (chock_broker.git_shim.needsNetwork(ask.subcommand)) {
            return try chock_broker.git_shim.hostReachingRefusal(gpa, ask.subcommand);
        }
        return null;
    }

    fn armPush(
        self: *GitToolRunner,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
        rest: []const []const u8,
    ) std.mem.Allocator.Error!?[]u8 {
        const creds = self.credentials orelse return try gpa.dupe(u8, credentials_not_wired_text);
        return switch (try creds.arm(gpa, io, self.project_root, call.call_id, rest)) {
            .ready => null,
            .refused => |text| text,
        };
    }
};

/// A language server is long lived and stateful and the registry knows nothing
/// that outlives one call, so the caller that owns the session holds it.
const DiagnosticToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    session: *chock_core.lsp.Session,

    fn runner(self: *DiagnosticToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *DiagnosticToolRunner = @ptrCast(@alignCast(ptr));
        const result = try self.inner.dispatch(gpa, io, call);

        if (result.is_error) return result;

        errdefer {
            gpa.free(result.call_id);
            gpa.free(result.output);
        }

        const path = (try chock_core.tools.writtenPathIn(gpa, call.tool, call.arguments)) orelse
            return result;
        defer gpa.free(path);

        const block = (try self.session.afterWrite(gpa, io, path)) orelse return result;
        defer gpa.free(block);

        const joined = try std.mem.concat(gpa, u8, &.{ result.output, block });
        gpa.free(result.output);

        var with_diagnostics = result;
        with_diagnostics.output = joined;
        return with_diagnostics;
    }
};

/// Outside every runner that reads a tool name and acts on it, so a name a third
/// party program chose never reaches the sandbox runner, the git shim or the
/// provisioner.
const McpToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    state: *McpState,
    said_changed: bool = false,

    fn runner(self: *McpToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *McpToolRunner = @ptrCast(@alignCast(ptr));

        const outcome = (try self.state.session.dispatch(gpa, io, call)) orelse
            return self.inner.dispatch(gpa, io, call);

        self.noteWidening();

        errdefer gpa.free(outcome.text);
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = outcome.text,
            .is_error = outcome.is_error,
            .truncated = false,
        };
    }

    fn noteWidening(self: *McpToolRunner) void {
        if (self.said_changed) return;
        var index: usize = 0;
        while (index < self.state.count) : (index += 1) {
            if (self.state.drivers[index].protocol.list_changed == 0) continue;
            self.said_changed = true;
            tty.print(
                .warn,
                "chock: the MCP server {s} says its tools have changed. This session keeps the " ++
                    "list it started with: a tool that appears now would widen what the agent " ++
                    "may do, and nothing can authorise that while a turn is running.\n",
                .{self.state.records[index].name},
            );
            return;
        }
    }
};

/// The arrays are fixed and never reallocated: a `chock_core.mcp.Server` points
/// at the driver beside it and that driver at the helper beside it, so a list
/// that grew would move both out from under the pointers.
const McpState = struct {
    session: chock_core.mcp.Session,
    arena: std.heap.ArenaAllocator,

    helpers: [chock_core.mcp.max_servers]chock_core.helper.Helper = undefined,
    drivers: [chock_core.mcp.max_servers]chock_core.mcp_driver.Driver = undefined,
    networks: [chock_core.mcp.max_servers]chock_broker.network.Network = undefined,
    transports: [chock_core.mcp.max_servers]chock_broker.network.System = undefined,
    records: [chock_core.mcp.max_servers]chock_core.mcp.Server = undefined,
    count: usize = 0,

    fn init(gpa: std.mem.Allocator) McpState {
        return .{ .session = .init(gpa), .arena = .init(gpa) };
    }

    fn deinit(self: *McpState, io: std.Io) void {
        const gpa = self.arena.child_allocator;

        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            self.helpers[index].deinit(io);
            self.drivers[index].deinit();

            // A refused connection has no other moment to be read: the network
            // broker answers from inside `Sandbox.spawn`, with the session's own
            // loop waiting on that call, so nothing can print when it happens.
            const network = &self.networks[index];
            if (network.refused != 0) {
                tty.print(
                    .warn,
                    "chock: the MCP server {s} was refused {d} of {d} connections it asked for.\n",
                    .{ self.records[index].name, network.refused, network.refused + network.granted },
                );
            }
            if (network.diagnostic) |*one| {
                tty.print(.warn, "chock: the first was {f}\n", .{one});
                one.deinit(gpa);
            }
        }
        self.session.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};

const TablePolicy = struct {
    policy: *const chock_policy.table.Table,
    chain: []const []const u8,
    agent_kind: []const u8,
    model: []const u8,

    fn decider(self: *TablePolicy) chock_core.mcp.Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.mcp.Decider.VTable{ .decide = decideFn };

    fn decideFn(ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        const self: *TablePolicy = @ptrCast(@alignCast(ptr));
        return self.answer(tool, action);
    }

    fn answer(
        self: *TablePolicy,
        tool: []const u8,
        action: []const u8,
    ) chock_policy.table.Decision {
        var fault: ?chock_policy.table.ChainFault = null;
        const decision = self.policy.evaluateChain(self.chain, .{
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = tool,
            .action = action,
        }, &fault);
        if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});
        return decision;
    }
};

/// The promises of the sessions above this one are read at session start rather
/// than per call, which is exact: a parent is blocked inside its own
/// `spawn_agent` call for the whole life of a child.
/// The search seam, filled only when the operator's own `config.zon` names an
/// engine. A null searcher is what `Loop` reports as no engine configured.
const SessionSearcher = struct {
    session: chock_broker.search.Session,

    fn searcher(self: *SessionSearcher) chock_core.search.Searcher {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.search.Searcher.VTable{ .search = searchFn };

    fn searchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        ask: chock_core.search.Ask,
    ) chock_core.search.Error!chock_core.search.Answer {
        const self: *SessionSearcher = @ptrCast(@alignCast(ptr));
        // The broker's own `Ask` carries the query alone: the policy question
        // was already answered live at the tool call, so nothing here reads a
        // promise or a tool name.
        const answered = try self.session.search(gpa, io, .{ .query = ask.query });
        return .{ .text = answered.text, .is_error = answered.is_error };
    }
};

const SessionFetcher = struct {
    gpa: std.mem.Allocator,
    session: chock_broker.fetch.Session,
    ancestors: []const chock_policy.ratchet.Restriction = &.{},

    fn deinit(self: *SessionFetcher) void {
        self.session.deinit();
    }

    fn fetcher(self: *SessionFetcher) chock_core.fetch.Fetcher {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.fetch.Fetcher.VTable{ .fetch = fetchFn };

    fn fetchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        ask: chock_core.fetch.Ask,
    ) chock_core.fetch.Error!chock_core.fetch.Answer {
        const self: *SessionFetcher = @ptrCast(@alignCast(ptr));

        self.session.tool = ask.tool;

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var promised: std.ArrayList(chock_policy.ratchet.Restriction) = .empty;
        try promised.appendSlice(arena, ask.self_policy);
        try promised.appendSlice(arena, self.ancestors);

        var diag: ?chock_broker.Diagnostic = null;
        defer if (diag) |*one| one.deinit(self.gpa);

        var outcome = try self.session.fetch(io, .{
            .url = ask.url,
            .self_policy = promised.items,
            .ask_host = if (ask.ask_host) |one| .{ .ptr = one.ptr, .call = one.call } else null,
        }, &diag);
        defer outcome.deinit(self.gpa);

        const note: []u8 = if (diag) |*one|
            try std.fmt.allocPrint(gpa, "{f}", .{one})
        else
            &.{};
        errdefer if (note.len != 0) gpa.free(note);

        return switch (outcome) {
            .refused => |refusal| .{
                .text = try gpa.dupe(u8, refusal.text),
                .is_error = true,
                .note = note,
            },
            .fetched => |page| .{
                .text = try chock_core.fetch.textForModel(gpa, page.url, page.status, page.body),
                .is_error = false,
                .note = note,
            },
        };
    }
};

/// A server keeps `Sandbox.Config.network` at `none` and reaches the network only
/// when this project's policy answers `allow` for `mcp.<server>.network`, and
/// even then reaches nothing until a `net.connect.*` rule names a host.
fn policyChain(
    keep: std.mem.Allocator,
    started: *const Started,
    options: Options,
) std.mem.Allocator.Error![]const []const u8 {
    const chain = try keep.alloc([]const u8, started.spawn_chain.len + 1);
    for (started.spawn_chain, chain[0..started.spawn_chain.len]) |link, *slot| {
        slot.* = link.agent_kind;
    }
    chain[started.spawn_chain.len] = options.agent_kind;
    return chain;
}

fn startMcp(
    gpa: std.mem.Allocator,
    io: std.Io,
    started: *Started,
    options: Options,
    context: *const chock_core.tools.Context,
    state: *McpState,
) std.mem.Allocator.Error!struct { []chock_core.tools.Definition, []const u8 } {
    const settings = started.mcp_servers orelse
        return .{ started.tool_definitions, started.system_prompt };

    const keep = state.arena.allocator();

    const chain = try policyChain(keep, started, options);
    var policy = TablePolicy{
        .policy = started.policy,
        .chain = chain,
        .agent_kind = options.agent_kind,
        .model = started.model,
    };

    for (settings) |one| {
        std.debug.assert(state.count < chock_core.mcp.max_servers);

        const prepared = blk: {
            const with_store = chock_core.tools.withStore(
                keep,
                io,
                started.sandbox_config,
                context.store_paths,
                context.toolchain_mounts,
            ) catch break :blk null;
            break :blk chock_core.tools.prepare(
                keep,
                io,
                started.tool_env,
                with_store,
                one.command,
                &.{},
                &.{},
            ) catch |err| {
                tty.print(
                    .warn,
                    "chock: the MCP server {s} ({s}) could not be prepared ({t}), so its tools " ++
                        "are not in this session.\n",
                    .{ one.name, one.command[0], err },
                );
                break :blk null;
            };
        } orelse continue;

        var config = prepared.config;
        const index = state.count;

        state.transports[index] = .{};
        state.networks[index] = .{
            .gpa = gpa,
            .io = io,
            .table = started.policy,
            .chain = chain,
            .agent_kind = options.agent_kind,
            .model = started.model,
            .tool = one.name,
            .transport = state.transports[index].transport(),
        };

        var buffer: [chock_core.mcp.max_action_bytes]u8 = undefined;
        const net_action = chock_core.mcp.networkActionInto(&buffer, one.name).?;
        if (policy.answer(one.name, net_action) == .allow) {
            config.network = .filtered;
            config.net_router = state.networks[index].netRouter();
            tty.detail(
                "chock: the MCP server {s} may reach the hosts this project's net.connect rules name\n",
                .{one.name},
            );
        }

        state.helpers[index] = chock_core.helper.Helper.init(std.heap.page_allocator);
        state.drivers[index] = chock_core.mcp_driver.Driver.init(
            gpa,
            &state.helpers[index],
            .{ .config = config, .argv = prepared.argv },
        );
        state.records[index] = .{ .name = one.name, .host = state.drivers[index].host() };
        state.count += 1;
    }

    state.session.servers = state.records[0..state.count];

    var discovery = std.heap.ArenaAllocator.init(gpa);
    defer discovery.deinit();

    for (state.session.servers) |*server| {
        const declared = server.host.list(
            discovery.allocator(),
            io,
            chock_core.mcp.discovery_budget_ns,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Late, error.Gone => {
                server.failure = if (err == error.Late)
                    chock_core.mcp.discovery_late
                else
                    chock_core.mcp.start_failed;
                tty.print(
                    .warn,
                    "chock: the MCP server {s}: {s}\n",
                    .{ server.name, server.failure.? },
                );
                continue;
            },
        };
        try state.session.admit(server, declared, policy.decider());
        if (server.failure) |reason| {
            tty.print(.warn, "chock: the MCP server {s}: {s}\n", .{ server.name, reason });
        }
    }

    reportMcpOffers(&state.session);

    var list: std.ArrayList(chock_core.tools.Definition) = .empty;
    try list.appendSlice(keep, started.tool_definitions);
    try state.session.appendDefinitions(keep, &list);
    const definitions = try list.toOwnedSlice(keep);

    const prompt = try chock_core.prompt.build(
        keep,
        started.prompt_project,
        definitions,
        started.prompt_sources,
    );
    return .{ definitions, prompt };
}

fn reportMcpOffers(session: *const chock_core.mcp.Session) void {
    if (session.isEmpty()) return;

    var offered: usize = 0;
    var asking: usize = 0;
    for (session.offers.items) |offer| {
        if (offer.refused != null) continue;
        offered += 1;
        if (offer.decision != .allow) asking += 1;
    }
    tty.detail("chock: {d} MCP tools in this session\n", .{offered});
    if (asking != 0) tty.detail(
        "chock: {d} of them ask before each call, because this project's policy does not allow them outright\n",
        .{asking},
    );

    for (session.offers.items) |offer| {
        const reason = offer.refused orelse continue;
        tty.detail(
            "chock: the MCP tool {s} of {s} is not offered, because {s}\n",
            .{ offer.name, offer.server, reason.text() },
        );
    }
}

// A plugin's tool list is read out of its own module file with no engine at all,
// so a plugin that is never called starts no process. A wasm guest owns the
// address space of the process that runs it in the engine this project has, so
// its sandbox is built by taking things away.

const plugin_module_target = "/plugin.wasm";

const plugin_host_target = "/chock";

/// Outside the MCP runner, so a name a plugin declared reaches nothing else at
/// all. `startPlugins` fills `chock_core.plugin.Session.reserved` with what MCP
/// got first, so the two lists are disjoint before either runner sees a call.
const PluginToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    state: *PluginState,

    fn runner(self: *PluginToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *PluginToolRunner = @ptrCast(@alignCast(ptr));

        const outcome = (try self.state.session.dispatch(gpa, io, call)) orelse
            return self.inner.dispatch(gpa, io, call);

        errdefer gpa.free(outcome.text);
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = outcome.text,
            .is_error = outcome.is_error,
            .truncated = false,
        };
    }
};

const PluginState = struct {
    session: chock_core.plugin.Session,
    arena: std.heap.ArenaAllocator,

    helpers: [chock_core.plugin.max_plugins]chock_core.helper.Helper = undefined,
    drivers: [chock_core.plugin.max_plugins]chock_core.plugin_host.Driver = undefined,
    records: [chock_core.plugin.max_plugins]chock_core.plugin.Loaded = undefined,
    count: usize = 0,

    fn init(gpa: std.mem.Allocator) PluginState {
        return .{ .session = .init(gpa), .arena = .init(gpa) };
    }

    fn deinit(self: *PluginState, io: std.Io) void {
        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            self.helpers[index].deinit(io);
            self.drivers[index].deinit();
        }
        self.session.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Plugins come last, so an MCP server already in the session keeps every name it
/// declared. Nothing here starts a process: the host process starts on the first
/// call of a tool.
fn startPlugins(
    gpa: std.mem.Allocator,
    io: std.Io,
    started: *Started,
    options: Options,
    context: *const chock_core.tools.Context,
    state: *PluginState,
    mcp_session: *const chock_core.mcp.Session,
    definitions: []chock_core.tools.Definition,
    prompt: []const u8,
) std.mem.Allocator.Error!struct { []chock_core.tools.Definition, []const u8 } {
    const settings = started.plugins orelse return .{ definitions, prompt };

    // There is no plugin on Darwin today, because a plugin host is a
    // sandboxed process and `Sandbox.spawn` refuses there. Said once, and
    // never as a tool the model is offered and cannot use.
    if (builtin.target.os.tag != .linux) {
        tty.print(
            .warn,
            "chock: a plugin runs in a sandbox of its own, and this platform has none, so no " ++
                "plugin is in this session.\n",
            .{},
        );
        return .{ definitions, prompt };
    }

    const keep = state.arena.allocator();

    var policy = TablePolicy{
        .policy = started.policy,
        .chain = try policyChain(keep, started, options),
        .agent_kind = options.agent_kind,
        .model = started.model,
    };

    const host_path = try chock_core.plugin_host.selfProgramPath(keep, io, started.exe_path) orelse {
        tty.print(
            .warn,
            "chock: this program's own path could not be resolved, so no plugin is in this " ++
                "session.\n",
            .{},
        );
        return .{ definitions, prompt };
    };

    state.session.reserved = try reservedNames(keep, mcp_session);

    for (settings) |one| {
        std.debug.assert(state.count < chock_core.plugin.max_plugins);

        const named = if (std.fs.path.isAbsolute(one.module))
            one.module
        else
            try std.fs.path.join(keep, &.{ started.project_root, one.module });
        const module_path = std.Io.Dir.cwd().realPathFileAlloc(io, named, keep) catch |err| {
            tty.print(
                .warn,
                "chock: the plugin {s} ({s}) could not be found ({t}), so its tools are not in " ++
                    "this session.\n",
                .{ one.name, named, err },
            );
            continue;
        };

        var reading = std.heap.ArenaAllocator.init(gpa);
        defer reading.deinit();
        const bytes = std.Io.Dir.cwd().readFileAlloc(
            io,
            module_path,
            reading.allocator(),
            .limited(chock_core.plugin_module.max_module_bytes),
        ) catch |err| {
            tty.print(
                .warn,
                "chock: the plugin {s} ({s}) could not be read ({t}), so its tools are not in " ++
                    "this session.\n",
                .{ one.name, module_path, err },
            );
            continue;
        };

        const config = try pluginSandbox(
            keep,
            io,
            started.sandbox_config,
            context.store_paths,
            context.toolchain_mounts,
            host_path,
            module_path,
        );

        var module_refusal: ?chock_core.plugin_module.Refusal = null;
        var failure: ?chock_core.plugin.Failure = null;
        var read = state.session.load(
            gpa,
            one.name,
            bytes,
            policy.decider(),
            &module_refusal,
            &failure,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                if (module_refusal) |detail| {
                    tty.print(
                        .warn,
                        "chock: the plugin {s} is not in this session: {f}\n",
                        .{ one.name, detail },
                    );
                } else {
                    tty.print(
                        .warn,
                        "chock: the plugin {s} is not in this session: its module could not be " ++
                            "read ({t})\n",
                        .{ one.name, err },
                    );
                }
                continue;
            },
        };
        read.deinit();

        if (failure) |why| {
            tty.print(
                .warn,
                "chock: the plugin {s} is not in this session, because {s}\n",
                .{ one.name, why.text() },
            );
            continue;
        }

        // Every capability its offered tools declared, and no other. The list is
        // fixed on argv before the process exists, so nothing the guest does and
        // nothing on the pipe can widen it.
        const capabilities = try chock_core.plugin_engine.unionOfCapabilities(
            keep,
            &state.session,
            one.name,
        );
        const argv = try pluginArgv(keep, capabilities);

        const index = state.count;
        state.helpers[index] = chock_core.helper.Helper.init(std.heap.page_allocator);
        state.drivers[index] = chock_core.plugin_host.Driver.init(
            gpa,
            &state.helpers[index],
            .{ .config = config, .argv = argv },
        );
        state.records[index] = .{ .name = one.name, .host = state.drivers[index].host() };
        state.count += 1;
    }

    state.session.plugins = state.records[0..state.count];
    reportPluginOffers(&state.session);

    if (state.session.isEmpty()) return .{ definitions, prompt };

    var list: std.ArrayList(chock_core.tools.Definition) = .empty;
    try list.appendSlice(keep, definitions);
    try state.session.appendDefinitions(keep, &list);
    const with_plugins = try list.toOwnedSlice(keep);

    return .{
        with_plugins,
        try chock_core.prompt.build(
            keep,
            started.prompt_project,
            with_plugins,
            started.prompt_sources,
        ),
    };
}

/// The supplier already in the session keeps its names, and a plugin tool of the
/// same name is refused with a reason the model reads.
fn reservedNames(
    keep: std.mem.Allocator,
    mcp_session: *const chock_core.mcp.Session,
) std.mem.Allocator.Error![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    for (mcp_session.offers.items) |offer| {
        if (offer.refused != null) continue;
        try names.append(keep, offer.name);
    }
    return names.toOwnedSlice(keep);
}

fn pluginArgv(
    keep: std.mem.Allocator,
    capabilities: []const []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(keep, plugin_host_target);
    try argv.append(keep, chock_core.plugin_host.verb);
    try argv.append(keep, plugin_module_target);
    try argv.appendSlice(keep, capabilities);
    return argv.toOwnedSlice(keep);
}

/// The sandbox one plugin host process runs in, built by taking things away from
/// the config a tool call gets. The host program carries the execute right,
/// without which `execve` on it is refused before one instruction runs. The
/// workspace is not in it: its mounts come through with no rule, present and
/// unreachable.
fn pluginSandbox(
    keep: std.mem.Allocator,
    io: std.Io,
    workspace_config: sandbox.Config,
    store_paths: []const []const u8,
    toolchain_mounts: []const chock_core.tools.ToolchainMount,
    host_path: []const u8,
    module_path: []const u8,
) std.mem.Allocator.Error!sandbox.Config {
    var base = workspace_config;
    base.cwd = "/";
    base.rules = &.{};

    const with_store = try chock_core.tools.withStore(keep, io, base, store_paths, toolchain_mounts);

    var mounts: std.ArrayList(sandbox.namespace.Mount) = .empty;
    try mounts.appendSlice(keep, with_store.mounts);
    try mounts.append(keep, .{ .bind = .{
        .source = host_path,
        .target = plugin_host_target,
        .read_only = true,
    } });
    try mounts.append(keep, .{ .bind = .{
        .source = module_path,
        .target = plugin_module_target,
        .read_only = true,
    } });

    var reach: std.ArrayList(sandbox.Config.Rule) = .empty;
    try reach.appendSlice(keep, with_store.rules);
    // A file and not a directory, so the rule cannot carry the `read_dir` right:
    // `landlock_add_rule` answers EINVAL for a directory right over a file.
    try reach.append(keep, .{
        .path = plugin_host_target,
        .access = .{ .execute = true, .read_file = true },
    });
    try reach.append(keep, .{
        .path = plugin_module_target,
        .access = .{ .read_file = true },
    });

    var config = try chock_core.plugin_host.lockdown(keep, with_store, reach.items);
    config.mounts = try mounts.toOwnedSlice(keep);
    return config;
}

fn reportPluginOffers(session: *const chock_core.plugin.Session) void {
    if (session.isEmpty()) return;

    var offered: usize = 0;
    var asking: usize = 0;
    for (session.offers.items) |offer| {
        if (offer.refused != null) continue;
        offered += 1;
        if (offer.decision != .allow) asking += 1;
    }
    tty.detail("chock: {d} plugin tools in this session\n", .{offered});
    if (asking != 0) tty.detail(
        "chock: {d} of them ask before each call, because this project's policy does not allow them outright\n",
        .{asking},
    );

    for (session.offers.items) |offer| {
        const reason = offer.refused orelse continue;
        tty.detail(
            "chock: the plugin tool {s} of {s} is not offered, because {s}\n",
            .{ offer.name, offer.plugin, reason.text() },
        );
    }
}

/// There is no long lived sandbox: every tool call builds its own
/// `sandbox.Config`, so a store path added between two calls is mounted by the
/// second. It reaches neither a background task already running, which deep
/// copied its config, nor a subagent, nor the next session.
const ProvisionToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    settings: ?Provisioning,
    arena: std.mem.Allocator,
    host_env: *const std.process.Environ.Map,
    environ: std.process.Environ,
    mounts: *SessionMounts,
    already: std.ArrayList([]const u8) = .empty,

    fn runner(self: *ProvisionToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *ProvisionToolRunner = @ptrCast(@alignCast(ptr));
        if (!std.mem.eql(u8, call.tool, @tagName(chock_core.tools.Tool.provide_tool))) {
            return self.inner.dispatch(gpa, io, call);
        }

        const answer = try self.provide(gpa, call);
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = answer.text,
            .is_error = answer.refused,
            .truncated = false,
        };
    }

    const Answer = struct { text: []u8, refused: bool };

    fn provide(
        self: *ProvisionToolRunner,
        gpa: std.mem.Allocator,
        call: chock_proto.event.ToolCall,
    ) std.mem.Allocator.Error!Answer {
        const settings = self.settings orelse return .{
            .text = try gpa.dupe(u8, provisioning_is_off),
            .refused = true,
        };

        const parsed = std.json.parseFromSlice(
            chock_core.tools.ProvideToolArgs,
            gpa,
            call.arguments,
            .{ .ignore_unknown_fields = true },
        ) catch return .{
            .text = try gpa.dupe(u8, "the arguments of provide_tool did not parse. Send one " ++
                "field, \"program\", holding the package name alone."),
            .refused = true,
        };
        defer parsed.deinit();

        const program = parsed.value.program;
        for (self.already.items) |name| {
            if (!std.mem.eql(u8, name, program)) continue;
            return .{
                .text = try std.fmt.allocPrint(
                    gpa,
                    "{s} is already in this session's toolchain, so nothing was done. Run it.",
                    .{program},
                ),
                .refused = false,
            };
        }

        tty.print(.plain, "chock: resolving {s} with nix, which can take some time\n", .{program});

        const resolved = self.resolveWithNix(settings, program) catch |err| return .{
            .text = try std.fmt.allocPrint(
                gpa,
                "{s} could not be resolved ({t}), so nothing was added to the toolchain. Do the " ++
                    "work with a program the toolchain already has.",
                .{ program, err },
            ),
            .refused = true,
        };

        const provided = switch (resolved) {
            .refused => |text| {
                tty.print(.warn, "chock: {s} was not provisioned\n", .{program});
                return .{ .text = try gpa.dupe(u8, text), .refused = true };
            },
            .provided => |one| one,
        };

        try self.adopt(program, provided);

        tty.print(.plain, "chock: {s} is in the toolchain, {d} store paths, {d} mounted in all\n", .{
            program,
            provided.store_paths.len,
            self.mounts.paths.items.len,
        });

        return .{
            .text = try std.fmt.allocPrint(
                gpa,
                "{s} is now in this session's toolchain, from {s}. Every call after this one can " ++
                    "run it. A background task or a subagent that was already running does not " ++
                    "have it, and it is gone at the end of this session: to keep it, tell the " ++
                    "user to add it to flake.nix.",
                .{ program, provided.installable },
            ),
            .refused = false,
        };
    }

    fn adopt(
        self: *ProvisionToolRunner,
        program: []const u8,
        provided: chock_nix.provision.Provided,
    ) std.mem.Allocator.Error!void {
        try self.mounts.adopt(provided);
        try self.already.append(self.arena, try self.arena.dupe(u8, program));
    }

    fn resolveWithNix(
        self: *ProvisionToolRunner,
        settings: Provisioning,
        program: []const u8,
    ) chock_nix.provision.Error!chock_nix.provision.Answer {
        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = self.environ });
        defer threaded.deinit();
        const io = threaded.io();

        var run_diag: ?chock_nix.Diagnostic = null;
        defer if (run_diag) |*d| d.deinit(self.arena);
        var host = chock_nix.provision.Host{
            .nix_program = settings.nix_program,
            .env = self.host_env,
            .diag = &run_diag,
        };
        const answer = chock_nix.provision.resolve(self.arena, io, host.runner(), .{
            .program = program,
            .registry = settings.registry,
        }) catch |err| {
            if (run_diag) |*fault| tty.print(.warn, "chock: {f}\n", .{fault});
            return err;
        };

        // Held against the garbage collector before the model is told it is
        // there. `nix build --no-link` leaves no root of its own, so a
        // `nix-collect-garbage` before the next tool call would take a toolchain
        // the agent has already been promised.
        if (answer == .provided) self.rootProvided(io, settings, program, answer.provided);
        return answer;
    }

    fn rootProvided(
        self: *ProvisionToolRunner,
        io: std.Io,
        settings: Provisioning,
        program: []const u8,
        provided: chock_nix.provision.Provided,
    ) void {
        const nix_store = settings.nix_store_program orelse return;
        const dir = settings.root_dir orelse return;

        const link_prefix = providedRootPrefix(self.arena, dir, program) catch return;
        var diag: ?chock_nix.Diagnostic = null;
        defer if (diag) |*d| d.deinit(self.arena);
        chock_nix.store.addRoots(
            self.arena,
            io,
            nix_store,
            self.host_env,
            link_prefix,
            provided.store_paths,
            &diag,
        ) catch |err| {
            if (diag) |*fault| {
                tty.print(
                    .warn,
                    "chock: {s} could not be held against the garbage collector ({f}). A " ++
                        "nix-collect-garbage during this session can break it.\n",
                    .{ program, fault },
                );
            } else {
                tty.print(
                    .warn,
                    "chock: {s} could not be held against the garbage collector ({t}). A " ++
                        "nix-collect-garbage during this session can break it.\n",
                    .{ program, err },
                );
            }
        };
    }
};

const SessionMounts = struct {
    arena: std.mem.Allocator,
    context: *chock_core.tools.Context,
    tool_env: *std.process.Environ.Map,
    /// Every store path this session mounts, with no repeats. A new package's
    /// closure and the dev shell's overlap almost entirely, and `withStore`
    /// builds one bind mount and one Landlock rule per entry.
    paths: std.ArrayList([]const u8) = .empty,
    mounted: std.StringHashMapUnmanaged(void) = .empty,

    fn adopt(
        self: *SessionMounts,
        provided: chock_nix.provision.Provided,
    ) std.mem.Allocator.Error!void {
        for (provided.store_paths) |path| try self.mount(path);
        self.context.store_paths = self.paths.items;
        try self.extendPath(provided.bin_dirs);
    }

    fn mount(self: *SessionMounts, path: []const u8) std.mem.Allocator.Error!void {
        const entry = try self.mounted.getOrPut(self.arena, path);
        if (entry.found_existing) return;
        entry.key_ptr.* = path;
        try self.paths.append(self.arena, path);
    }

    fn start(self: *SessionMounts, paths: []const []const u8) std.mem.Allocator.Error!void {
        for (paths) |path| try self.mount(path);
    }

    fn extendPath(self: *SessionMounts, dirs: []const []const u8) std.mem.Allocator.Error!void {
        var joined: std.ArrayList(u8) = .empty;
        for (dirs) |dir| {
            try joined.appendSlice(self.arena, dir);
            try joined.append(self.arena, ':');
        }
        try joined.appendSlice(self.arena, self.tool_env.get("PATH") orelse "");
        try self.tool_env.put("PATH", joined.items);
    }
};

/// `nix-store --add-root` names its links after the prefix it is given, so two
/// programs sharing one prefix means the second call replaces the first one's
/// links and a program the agent is still using stops being held.
fn providedRootPrefix(
    arena: std.mem.Allocator,
    dir: []const u8,
    program: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}-provided-{s}", .{
        dir,
        chock_nix.DevShell.root_link_name,
        program,
    });
}

const provisioning_is_off = "no program was provisioned: this session cannot add one. Do the " ++
    "work with a program the toolchain already has, and do not run apt, npm, pip, cargo or " ++
    "brew, because none of them can work in this sandbox.";

/// An evaluation runs in this process, outside every sandbox. Store writes stay
/// off, and the driver is installed with `Seam.refusing`, so an evaluation that
/// reaches for a store gets a refusal that names the path, which import from
/// derivation needs. One engine per call, because an engine holds every value.
const NixEvalToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    settings: ?NixEval,

    fn runner(self: *NixEvalToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *NixEvalToolRunner = @ptrCast(@alignCast(ptr));
        if (!std.mem.eql(u8, call.tool, @tagName(chock_core.tools.Tool.nix_eval))) {
            return self.inner.dispatch(gpa, io, call);
        }

        const answer = try self.evaluate(gpa, io, call);
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = answer.text,
            .is_error = answer.refused,
            .truncated = false,
        };
    }

    const Answer = struct { text: []u8, refused: bool };

    fn evaluate(
        self: *NixEvalToolRunner,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) std.mem.Allocator.Error!Answer {
        const settings = self.settings orelse return .{
            .text = try gpa.dupe(u8, nix_eval_is_off),
            .refused = true,
        };

        const parsed = std.json.parseFromSlice(
            chock_core.tools.NixEvalArgs,
            gpa,
            call.arguments,
            .{ .ignore_unknown_fields = true },
        ) catch return .{
            .text = try gpa.dupe(u8, "the arguments of nix_eval did not parse. Send one field, " ++
                "\"expression\", holding the expression alone."),
            .refused = true,
        };
        defer parsed.deinit();

        return settings.run(gpa, io, parsed.value.expression);
    }
};

const NixEval = struct {
    workspace_root: []const u8,
    caps: chock_policy.nix.Resolved,

    fn driverFor(self: NixEval, gpa: std.mem.Allocator) chock_nix.backend.Driver {
        var driver = chock_nix.backend.Driver.init(gpa, chock_nix.backend.Seam.refusing);
        applyNixCaps(&driver, self.caps);
        return driver;
    }

    fn run(
        self: NixEval,
        gpa: std.mem.Allocator,
        io: std.Io,
        expression: []const u8,
    ) std.mem.Allocator.Error!NixEvalToolRunner.Answer {
        var driver = self.driverFor(gpa);
        defer driver.deinit();

        var session = chock_nix.eval.Session.init(gpa, .{
            .roots = &.{self.workspace_root},
            .io = io,
            .store_backend = driver.backend(),
        }) catch |err| return .{
            .text = try std.fmt.allocPrint(
                gpa,
                "the evaluator could not be started ({t}), so nothing was evaluated.",
                .{err},
            ),
            .refused = true,
        };
        defer session.deinit();

        const buffer = try gpa.alloc(u8, chock_core.tools.max_nix_eval_bytes);
        defer gpa.free(buffer);

        const answer = session.answer(buffer, expression) catch |err| return .{
            .text = try nixEvalRefusal(gpa, &session, &driver, self.workspace_root, expression, err),
            .refused = true,
        };

        if (answer.derivation_path) |path| return .{
            .text = try std.fmt.allocPrint(
                gpa,
                "{s}\n\nThat is a derivation, and {s} is its derivation file. Nothing was " ++
                    "built: nix_eval evaluates and never builds.",
                .{ answer.text, path },
            ),
            .refused = false,
        };
        return .{ .text = try gpa.dupe(u8, answer.text), .refused = false };
    }
};

fn nixEvalRefusal(
    gpa: std.mem.Allocator,
    session: *chock_nix.eval.Session,
    driver: *chock_nix.backend.Driver,
    workspace_root: []const u8,
    expression: []const u8,
    err: anyerror,
) std.mem.Allocator.Error![]u8 {
    if (driver.lastError()) |said| return std.fmt.allocPrint(
        gpa,
        "the expression asked a Nix store for something, and this session has none: {s}. " ++
            "nix_eval works out what a derivation is and never builds one, so importing the " ++
            "result of a build cannot work here. Ask about the derivation itself, such as its " ++
            "drvPath, or do the work another way.",
        .{said},
    );

    if (err == error.WriteFailed) return std.fmt.allocPrint(
        gpa,
        "the value is longer than {d} bytes rendered, so nothing came back. Ask for the part " ++
            "of it you need, such as one attribute or builtins.attrNames of the set.",
        .{chock_core.tools.max_nix_eval_bytes},
    );

    if (err == error.RestrictedInPureEval) return std.fmt.allocPrint(
        gpa,
        "the expression reads something a pure evaluation may not: a path outside the " ++
            "workspace, the environment, or a channel. Only files under {s} can be read, and " ++
            "the workspace is the only tree there is.",
        .{workspace_root},
    );

    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(gpa);
    try text.print(gpa, "the expression was not evaluated ({t}).", .{err});

    var said: std.Io.Writer.Allocating = .init(gpa);
    defer said.deinit();
    session.writeDiagnostics(&said.writer, expression) catch {};
    if (said.written().len != 0) try text.print(gpa, "\n{s}", .{said.written()});
    return text.toOwnedSlice(gpa);
}

const nix_eval_is_off = "nothing was evaluated: this session cannot evaluate a Nix expression. " ++
    "Work from what is in the project instead.";

const NixBuild = struct {
    workspace_root: []const u8,
    caps: chock_policy.nix.Resolved,
    nix_program: []const u8,
    nix_store_program: ?[]const u8,
    root_dir: ?[]const u8,
    store_endpoint: []const u8,
    inputs: FlakeInputs,
};

fn nixBuildFor(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    dev_shell_dir: ?[]const u8,
    workspace_root: []const u8,
    caps: chock_policy.nix.Resolved,
    inputs: FlakeInputs,
) ?NixBuild {
    const nix_program = chock_nix.proc.resolve(arena, io, env, "nix") catch {
        tty.detail("chock: nix_build is off, because nix is not on this machine's PATH\n", .{});
        return null;
    };
    const nix_store_program = chock_nix.proc.resolve(arena, io, env, "nix-store") catch null;
    return .{
        .workspace_root = workspace_root,
        .caps = caps,
        .nix_program = nix_program,
        .nix_store_program = nix_store_program,
        .root_dir = dev_shell_dir,
        .store_endpoint = env.get("NIX_DAEMON_SOCKET_PATH") orelse
            chock_nix.build.default_daemon_socket,
        .inputs = inputs,
    };
}

/// A fixed output derivation builds with the network open to it, and its output
/// hash is integrity and never egress: a URL carrying a secret in its query
/// string, with the hash of an innocuous file, passes it. The names are `nix.net`
/// and never `net.connect`, so a rule that lets a build fetch from a host does
/// not let the agent's own sandbox open a socket to it.
const NixFetchGate = struct {
    const opaque_action = chock_broker.network.nix_opaque_action;

    const many_action = chock_broker.network.nix_action_prefix ++ ".hosts";

    gpa: std.mem.Allocator,
    io: std.Io,
    asker: ?chock_core.arbiter.Asker,
    installable: []const u8,
    call: chock_proto.event.ToolCall,
    kind: Kind = .derivation,
    rule: ?Rule = null,

    const Rule = struct {
        policy: *const chock_policy.table.Table,
        chain: []const []const u8,
        agent_kind: []const u8,
        model: []const u8,
    };

    const Kind = enum {
        derivation,
        flake_input,
    };

    fn phase(self: *const NixFetchGate) chock_broker.network.NixPhase {
        return switch (self.kind) {
            .derivation => .build,
            .flake_input => .eval,
        };
    }

    fn namesOf(
        self: *const NixFetchGate,
        scoped: []u8,
        either: []u8,
        one: chock_nix.fetch.Fetch,
    ) ?chock_broker.network.NixActions {
        return chock_broker.network.nixActionsInto(
            scoped,
            either,
            self.phase(),
            one.host,
            one.port,
        );
    }

    fn gate(self: *NixFetchGate) chock_nix.fetch.Gate {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_nix.fetch.Gate.VTable{
        .permit_all = permitAllFn,
        .permit_opaque = permitOpaqueFn,
        .rule_for = ruleForFn,
        .permit_site = permitSiteFn,
    };

    /// A nixpkgs closure reaches a hundred distinct hosts, and a hundred
    /// questions is one decision and ninety nine keystrokes. A host a rule
    /// already allows never appears in the question.
    fn permitAllFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        wanted: []const chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        const self: *NixFetchGate = @ptrCast(@alignCast(ptr));

        var asking: std.ArrayList(chock_nix.fetch.Fetch) = .empty;
        defer asking.deinit(self.gpa);

        for (wanted) |one| {
            var scoped: [chock_broker.network.max_action_bytes]u8 = undefined;
            var either: [chock_broker.network.max_action_bytes]u8 = undefined;
            if (self.namesOf(&scoped, &either, one) == null) {
                return .{ .refused = try self.unnameable(allocator, one) };
            }

            if (self.decisionFor(one)) |decision| {
                if (decision != .ask) {
                    switch (try self.decideOne(allocator, one)) {
                        .permitted => continue,
                        .refused => |why| return .{ .refused = why },
                    }
                }
            }
            try asking.append(self.gpa, one);
        }

        if (asking.items.len == 0) return .permitted;
        if (asking.items.len == 1) return self.decideOne(allocator, asking.items[0]);
        return self.decideMany(allocator, asking.items);
    }

    /// Whether this build may fetch without saying where it goes. A fixed
    /// output derivation's hash still proves the bytes are what the
    /// derivation expected. What it cannot prove is where the request went.
    fn permitOpaqueFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        subjects: []const []const u8,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        const self: *NixFetchGate = @ptrCast(@alignCast(ptr));
        std.debug.assert(subjects.len != 0);

        const summary = if (subjects.len == 1) try std.fmt.allocPrint(
            self.gpa,
            "a Nix build fetches without saying where from",
            .{},
        ) else try std.fmt.allocPrint(
            self.gpa,
            "{d} parts of a Nix build fetch without saying where from",
            .{subjects.len},
        );
        defer self.gpa.free(summary);

        const others = if (subjects.len == 1) try self.gpa.dupe(u8, "") else try std.fmt.allocPrint(
            self.gpa,
            " There are {d} of them in this closure, and this answer covers all of them.",
            .{subjects.len},
        );
        defer self.gpa.free(others);

        const detail = try std.fmt.allocPrint(
            self.gpa,
            "{s} fetches while it builds and names no URL anywhere, so no host of it can be " ++
                "put to a rule. Its output hash still proves the bytes are the ones the " ++
                "derivation expected. What nothing proves is where the request went.{s} The " ++
                "build is {s}.",
            .{ subjects[0], others, self.installable },
        );
        defer self.gpa.free(detail);

        const answer = chock_core.arbiter.Asker.decide(self.asker, self.gpa, self.io, .{
            .action = opaque_action,
            .summary = summary,
            .detail = detail,
            .reason = "",
            .tool = self.call.tool,
            .tool_call_id = self.call.call_id,
            .source = self.requestSource(),
        });
        if (answer.permitted) return .permitted;

        const said = try chock_core.arbiter.refusalText(self.gpa, opaque_action, answer);
        defer self.gpa.free(said);
        return .{ .refused = try allocator.dupe(u8, said) };
    }

    fn ruleForFn(ptr: *anyopaque, one: chock_nix.fetch.Fetch) chock_nix.fetch.RuleAnswer {
        const self: *NixFetchGate = @ptrCast(@alignCast(ptr));
        return ruleAnswerOf(self.decisionFor(one) orelse return .unsettled);
    }

    fn unnameable(
        self: *NixFetchGate,
        allocator: std.mem.Allocator,
        one: chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error![]const u8 {
        return switch (self.kind) {
            .derivation => std.fmt.allocPrint(
                allocator,
                "{s} fetches {s}, and \"{s}\" is not a host name a rule can be written " ++
                    "for, so nothing was fetched. Use an input whose host is an ordinary name.",
                .{ one.subject, one.url, one.host },
            ),
            .flake_input => std.fmt.allocPrint(
                allocator,
                "the flake input {s} comes from \"{s}\", which is not a host name a rule " ++
                    "can be written for, so nothing was fetched.",
                .{ one.subject, one.host },
            ),
        };
    }

    fn decisionFor(
        self: *NixFetchGate,
        one: chock_nix.fetch.Fetch,
    ) ?chock_policy.table.Decision {
        const rule = self.rule orelse return null;

        var scoped: [chock_broker.network.max_action_bytes]u8 = undefined;
        var either: [chock_broker.network.max_action_bytes]u8 = undefined;
        const names = self.namesOf(&scoped, &either, one) orelse return null;
        return self.readerFor(rule).decide(names);
    }

    fn readerFor(self: *const NixFetchGate, rule: Rule) NixTableReader {
        return .{
            .policy = rule.policy,
            .chain = rule.chain,
            .agent_kind = rule.agent_kind,
            .model = rule.model,
            .tool = self.call.tool,
        };
    }

    /// The key is the site and the hash of that site's own list, so a rule
    /// somebody wrote stops covering it the moment that list changes.
    fn permitSiteFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        site: chock_nix.fetch.MirrorSite,
        chosen: chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        const self: *NixFetchGate = @ptrCast(@alignCast(ptr));

        var buffer: [chock_broker.network.max_mirror_action_bytes]u8 = undefined;
        const action = chock_broker.network.mirrorActionInto(
            &buffer,
            site.site,
            &site.hash(),
        ) orelse return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} fetches {s}, and the site {s} is not a name a rule can be written for, so " ++
                "nothing was built.",
            .{ site.subject, site.url, site.site },
        ) };

        const summary = try std.fmt.allocPrint(
            self.gpa,
            "a Nix build fetches from the {s} mirrors, starting at {s}",
            .{ site.site, chosen.host },
        );
        defer self.gpa.free(summary);

        var detail: std.ArrayList(u8) = .empty;
        defer detail.deinit(self.gpa);
        try detail.print(
            self.gpa,
            "{s} fetches {s}. The mirrors file names {d} mirrors for the site {s}, and {s} is " ++
                "the one this build would use. Yes covers this list, and a bump to it asks " ++
                "again. The build is {s}. Every mirror of the site:\n",
            .{
                site.subject,
                site.url,
                site.mirrors.len,
                site.site,
                chosen.url,
                self.installable,
            },
        );
        for (site.mirrors) |mirror| try detail.print(self.gpa, "  {s}\n", .{mirror.base});

        const answer = chock_core.arbiter.Asker.decide(self.asker, self.gpa, self.io, .{
            .action = action,
            .summary = summary,
            .detail = detail.items,
            .reason = "",
            .tool = self.call.tool,
            .tool_call_id = self.call.call_id,
            .source = self.requestSource(),
        });
        if (answer.permitted) return .permitted;

        const said = try chock_core.arbiter.refusalText(self.gpa, action, answer);
        defer self.gpa.free(said);
        return .{ .refused = try allocator.dupe(u8, said) };
    }

    fn requestSource(self: *const NixFetchGate) []const u8 {
        return switch (self.kind) {
            .derivation => "a Nix build",
            .flake_input => "a Nix flake input",
        };
    }

    const hosts_in_summary: usize = 3;

    fn decideMany(
        self: *NixFetchGate,
        allocator: std.mem.Allocator,
        wanted: []const chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        std.debug.assert(wanted.len > 1);

        var summary: std.ArrayList(u8) = .empty;
        defer summary.deinit(self.gpa);
        try summary.print(self.gpa, "a Nix build fetches from {d} hosts: ", .{wanted.len});
        for (wanted[0..@min(wanted.len, hosts_in_summary)], 0..) |one, index| {
            if (index != 0) try summary.appendSlice(self.gpa, ", ");
            try summary.appendSlice(self.gpa, one.host);
        }
        if (wanted.len > hosts_in_summary) {
            try summary.print(self.gpa, " and {d} more", .{wanted.len - hosts_in_summary});
        }

        var detail: std.ArrayList(u8) = .empty;
        defer detail.deinit(self.gpa);
        try detail.print(
            self.gpa,
            "{s} fetches from {d} hosts while it builds. Yes covers these {d} for this build " ++
                "and nothing after it. Every one of them, and the rule this project would " ++
                "write in its own chock.zon to stop being asked:\n",
            .{ self.installable, wanted.len, wanted.len },
        );
        for (wanted) |one| {
            var scoped: [chock_broker.network.max_action_bytes]u8 = undefined;
            var either: [chock_broker.network.max_action_bytes]u8 = undefined;
            const names = self.namesOf(&scoped, &either, one) orelse continue;
            try detail.print(
                self.gpa,
                "  {s}  .{{ .action = \"{s}\", .decision = .allow }},\n",
                .{ one.host, names.phase },
            );
        }

        const answer = chock_core.arbiter.Asker.decide(self.asker, self.gpa, self.io, .{
            .action = many_action,
            .summary = summary.items,
            .detail = detail.items,
            .reason = "",
            .tool = self.call.tool,
            .tool_call_id = self.call.call_id,
            .source = self.requestSource(),
        });
        if (answer.permitted) return .permitted;

        const said = try chock_core.arbiter.refusalText(self.gpa, many_action, answer);
        defer self.gpa.free(said);

        var names: std.ArrayList(u8) = .empty;
        defer names.deinit(self.gpa);
        for (wanted[0..@min(wanted.len, hosts_in_summary)], 0..) |one, index| {
            if (index != 0) try names.appendSlice(self.gpa, ", ");
            try names.appendSlice(self.gpa, one.host);
        }
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "this build fetches from {d} hosts, {s} among them, and none of them was reached. {s}",
            .{ wanted.len, names.items, said },
        ) };
    }

    fn decideOne(
        self: *NixFetchGate,
        allocator: std.mem.Allocator,
        one: chock_nix.fetch.Fetch,
    ) std.mem.Allocator.Error!chock_nix.fetch.Verdict {
        var scoped: [chock_broker.network.max_action_bytes]u8 = undefined;
        var either: [chock_broker.network.max_action_bytes]u8 = undefined;
        const action = (self.namesOf(&scoped, &either, one) orelse
            return .{ .refused = try self.unnameable(allocator, one) }).phase;

        const summary = switch (self.kind) {
            .derivation => try std.fmt.allocPrint(
                self.gpa,
                "a Nix build fetches from {s}",
                .{one.host},
            ),
            .flake_input => try std.fmt.allocPrint(
                self.gpa,
                "a Nix build needs the flake input {s} from {s}",
                .{ one.subject, one.host },
            ),
        };
        defer self.gpa.free(summary);
        const detail = switch (self.kind) {
            .derivation => try std.fmt.allocPrint(
                self.gpa,
                "{s} fetches {s} while it builds, over port {d}. The build is {s}.",
                .{ one.subject, one.url, one.port, self.installable },
            ),
            .flake_input => try std.fmt.allocPrint(
                self.gpa,
                "the flake input {s} is fetched from {s}, over port {d}, before {s} can be " ++
                    "evaluated at all. This project's own flake.lock is what names it.",
                .{ one.subject, one.host, one.port, self.installable },
            ),
        };
        defer self.gpa.free(detail);

        const answer = chock_core.arbiter.Asker.decide(self.asker, self.gpa, self.io, .{
            .action = action,
            .summary = summary,
            .detail = detail,
            .reason = "",
            .tool = self.call.tool,
            .tool_call_id = self.call.call_id,
            .source = self.requestSource(),
        });
        if (answer.permitted) return .permitted;

        const said = try chock_core.arbiter.refusalText(self.gpa, action, answer);
        defer self.gpa.free(said);
        return .{ .refused = switch (self.kind) {
            .derivation => try std.fmt.allocPrint(
                allocator,
                "{s} fetches {s} from {s} while it builds. {s}",
                .{ one.subject, one.url, one.host, said },
            ),
            .flake_input => try std.fmt.allocPrint(
                allocator,
                "the flake input {s} comes from {s}. {s}",
                .{ one.subject, one.host, said },
            ),
        } };
    }
};

/// The attribute is evaluated in this process, with store writes on, and the
/// derivation closure is written into the host store through its daemon, which
/// registers the derivation so its produced set can authorise a build of it. A
/// path this session built still asks under `exec.nix.store.*`, because
/// `Loop.Deps.store_closure` is read from the toolchain the session started with.
const NixBuildToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    settings: ?NixBuild,
    arena: std.mem.Allocator,
    host_env: *const std.process.Environ.Map,
    environ: std.process.Environ,
    mounts: *SessionMounts,
    builds: usize = 0,
    budget: chock_nix.build.Budget = .{},
    asker: ?chock_core.arbiter.Asker = null,
    rule: ?NixFetchGate.Rule = null,

    fn runner(self: *NixBuildToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn giveLocked(self: *NixBuildToolRunner, locked: *chock_core.arbiter.Locked) void {
        if (self.asker) |*one| one.locked = locked;
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *NixBuildToolRunner = @ptrCast(@alignCast(ptr));
        if (!std.mem.eql(u8, call.tool, @tagName(chock_core.tools.Tool.nix_build))) {
            return self.inner.dispatch(gpa, io, call);
        }

        const answer = try self.build(gpa, io, call);
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = answer.text,
            .is_error = answer.refused,
            .truncated = false,
        };
    }

    const Answer = struct { text: []u8, refused: bool };

    fn build(
        self: *NixBuildToolRunner,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) std.mem.Allocator.Error!Answer {
        const settings = self.settings orelse return .{
            .text = try gpa.dupe(u8, nix_build_is_off),
            .refused = true,
        };

        const parsed = std.json.parseFromSlice(
            chock_core.tools.NixBuildArgs,
            gpa,
            call.arguments,
            .{ .ignore_unknown_fields = true },
        ) catch return .{
            .text = try gpa.dupe(u8, "the arguments of nix_build did not parse. Send " ++
                "\"attribute\" as a list of names, and \"flake\" only if you mean another " ++
                "flake."),
            .refused = true,
        };
        defer parsed.deinit();

        const attr_path = parsed.value.attribute;
        const flake_ref = parsed.value.flake orelse settings.workspace_root;

        chock_nix.build.checkAttrPath(attr_path) catch |err| return .{
            .text = try chock_nix.build.requestRefusal(gpa, err),
            .refused = true,
        };
        chock_nix.build.checkFlakeRef(flake_ref) catch |err| return .{
            .text = try chock_nix.build.requestRefusal(gpa, err),
            .refused = true,
        };
        if (!isWorkspaceFlake(settings.workspace_root, flake_ref)) return .{
            .text = try foreignFlakeRefusal(gpa, flake_ref),
            .refused = true,
        };

        const installable = try chock_nix.build.installableFor(self.arena, flake_ref, attr_path);
        const expression = try chock_nix.build.expressionFor(self.arena, flake_ref, attr_path);

        var driver = chock_nix.backend.Driver.init(gpa, chock_nix.backend.Seam.refusing);
        defer driver.deinit();
        applyNixCaps(&driver, settings.caps);

        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = self.environ });
        defer threaded.deinit();
        const host_io = threaded.io();

        var store_writer = chock_nix.build.DaemonWriter.connect(
            gpa,
            host_io,
            settings.store_endpoint,
        ) catch |err| return .{
            .text = try std.fmt.allocPrint(
                gpa,
                "{s} was not built: the Nix daemon at {s} could not be reached ({t}), and a " ++
                    "build puts the derivation it evaluated in the store through it. Do the " ++
                    "work with what the toolchain already has, and tell the user.",
                .{ installable, settings.store_endpoint, err },
            ),
            .refused = true,
        };
        defer store_writer.deinit();

        self.budget.max_bytes = settings.caps.max_session_bytes;
        var writing = chock_nix.build.Writing{
            .writer = store_writer.writer(),
            .budget = &self.budget,
            // What stops fix fetching a flake input for itself: it takes a locked
            // input out of the store when the store says the path is valid.
            .fetched_paths = settings.inputs.store_paths,
        };
        driver.seam = writing.seam();

        var gate = NixFetchGate{
            .gpa = gpa,
            .io = host_io,
            .asker = self.asker,
            .installable = installable,
            .call = call,
            .rule = self.rule,
        };
        var input_gate = NixFetchGate{
            .gpa = gpa,
            .io = host_io,
            .asker = self.asker,
            .installable = installable,
            .call = call,
            .kind = .flake_input,
            .rule = self.rule,
        };

        const drv_path = switch (try self.derivationOf(gpa, io, settings, &driver, expression, installable)) {
            .refused => |text| return .{ .text = text, .refused = true },
            .found => |path| path,
            // One retry, and never a loop. The session start fetches an input
            // only where the policy said `allow`, because there is nobody at the
            // prompt then, so this is the first moment a person can be asked.
            .inputs_missing => blk: {
                const now = try self.fetchInputs(host_io, settings, input_gate.gate(), installable);
                if (now.store_paths.len == 0) return .{
                    .text = try chock_nix.inputs.missingRefusal(
                        gpa,
                        installable,
                        now.missing,
                        now.wanted,
                    ),
                    .refused = true,
                };

                writing.fetched_paths = now.store_paths;
                if (self.settings) |*one| one.inputs = now;

                break :blk switch (try self.derivationOf(gpa, io, settings, &driver, expression, installable)) {
                    .refused => |text| return .{ .text = text, .refused = true },
                    .found => |path| path,
                    .inputs_missing => return .{
                        .text = try chock_nix.inputs.missingRefusal(
                            gpa,
                            installable,
                            "the inputs this project's lock names were fetched and the " ++
                                "evaluation still wanted one that is not among them.",
                            now.wanted,
                        ),
                        .refused = true,
                    },
                };
            },
        };

        tty.print(.plain, "chock: building {s} with nix, which can take some time\n", .{installable});

        const answer = self.realiseWithNix(host_io, settings, &driver, gate.gate(), .{
            .derivation_path = drv_path,
            .installable = installable,
        }) catch |err| return .{
            .text = try std.fmt.allocPrint(
                gpa,
                "{s} could not be built ({t}), so nothing was built. Do the work with what the " ++
                    "toolchain already has.",
                .{ installable, err },
            ),
            .refused = true,
        };

        const built = switch (answer) {
            .refused => |text| {
                tty.print(.warn, "chock: {s} was not built\n", .{installable});
                return .{ .text = try gpa.dupe(u8, text), .refused = true };
            },
            .built => |one| one,
        };

        try self.mounts.adopt(built.provided);

        tty.print(.plain, "chock: {s} is built, {d} store paths, {d} mounted in all\n", .{
            installable,
            built.provided.store_paths.len,
            self.mounts.paths.items.len,
        });

        return .{ .text = try builtText(gpa, installable, built), .refused = false };
    }

    const Derivation = union(enum) {
        found: []const u8,
        refused: []u8,
        inputs_missing,
    };

    /// This is where a startup `ask` stops being a permanent no: a build is a
    /// turn the model took, so there is somebody to ask. The fetch still happens
    /// on the host through `nix flake archive`, and fix never reaches the network
    /// itself. The workspace's own lock and not the project's.
    fn fetchInputs(
        self: *NixBuildToolRunner,
        io: std.Io,
        settings: NixBuild,
        gate: chock_nix.fetch.Gate,
        installable: []const u8,
    ) std.mem.Allocator.Error!FlakeInputs {
        const lock_bytes = readProjectLock(self.arena, io, settings.workspace_root) orelse return .{
            .missing = "there is no flake.lock in the workspace, so nothing says where its " ++
                "inputs come from.",
        };

        const wanted = switch (try chock_nix.inputs.wantsOf(self.arena, lock_bytes)) {
            .hosts => |list| list,
            else => &.{},
        };

        tty.print(
            .plain,
            "chock: {s} needs a flake input that is not in the store yet\n",
            .{installable},
        );

        var diag: ?chock_nix.Diagnostic = null;
        defer if (diag) |*one| one.deinit(self.arena);
        var host = chock_nix.provision.Host{
            .nix_program = settings.nix_program,
            .env = self.host_env,
            .diag = &diag,
        };

        const answer = chock_nix.inputs.fetchAll(
            self.arena,
            io,
            host.runner(),
            gate,
            settings.workspace_root,
            lock_bytes,
        ) catch {
            if (diag) |*fault| tty.print(.warn, "chock: {f}\n", .{fault});
            return .{
                .wanted = wanted,
                .missing = "nix could not be run, so the inputs were not fetched.",
            };
        };

        return switch (answer) {
            .fetched => |paths| .{ .store_paths = paths, .wanted = wanted },
            .refused => |why| .{ .wanted = wanted, .missing = why },
        };
    }

    fn derivationOf(
        self: *NixBuildToolRunner,
        gpa: std.mem.Allocator,
        io: std.Io,
        settings: NixBuild,
        driver: *chock_nix.backend.Driver,
        expression: []const u8,
        installable: []const u8,
    ) std.mem.Allocator.Error!Derivation {
        var session = chock_nix.eval.Session.init(gpa, .{
            .roots = &.{settings.workspace_root},
            .io = io,
            .store_backend = driver.backend(),
            .store_writes = true,
            // `network` stays off, so the inputs of that flake come out of the
            // store and never off a connection fix opened.
            .flakes = true,
        }) catch |err| return .{ .refused = try std.fmt.allocPrint(
            gpa,
            "the evaluator could not be started ({t}), so nothing was built.",
            .{err},
        ) };
        defer session.deinit();

        const buffer = try gpa.alloc(u8, chock_core.tools.max_nix_eval_bytes);
        defer gpa.free(buffer);

        const answer = session.answer(buffer, expression) catch |err| {
            if (err == error.FetchIoUnavailable) return .inputs_missing;
            return .{
                .refused = try nixBuildRefusal(gpa, &session, driver, installable, expression, err),
            };
        };

        const drv_path = answer.derivation_path orelse return .{ .refused = try std.fmt.allocPrint(
            gpa,
            "{s} is not a derivation, so there is nothing to build. It evaluated to {s}. Name " ++
                "an attribute that is a package.",
            .{ installable, answer.text },
        ) };

        session.ensureDerivation(drv_path) catch |err| {
            if (err == error.FetchIoUnavailable) return .inputs_missing;
            return .{
                .refused = try nixBuildRefusal(gpa, &session, driver, installable, expression, err),
            };
        };

        return .{ .found = try self.arena.dupe(u8, drv_path) };
    }

    fn realiseWithNix(
        self: *NixBuildToolRunner,
        io: std.Io,
        settings: NixBuild,
        driver: *chock_nix.backend.Driver,
        gate: chock_nix.fetch.Gate,
        request: chock_nix.build.Request,
    ) chock_nix.build.Error!chock_nix.build.Answer {
        var run_diag: ?chock_nix.Diagnostic = null;
        defer if (run_diag) |*d| d.deinit(self.arena);
        var host = chock_nix.provision.Host{
            .nix_program = settings.nix_program,
            .env = self.host_env,
            .diag = &run_diag,
        };

        const answer = chock_nix.build.realise(
            self.arena,
            io,
            host.runner(),
            driver,
            gate,
            request,
        ) catch |err| {
            if (run_diag) |*fault| tty.print(.warn, "chock: {f}\n", .{fault});
            return err;
        };

        if (answer == .built) self.rootBuilt(io, settings, request.installable, answer.built);
        return answer;
    }

    fn rootBuilt(
        self: *NixBuildToolRunner,
        io: std.Io,
        settings: NixBuild,
        installable: []const u8,
        built: chock_nix.build.Built,
    ) void {
        const nix_store = settings.nix_store_program orelse return;
        const dir = settings.root_dir orelse return;

        const link_prefix = builtRootPrefix(self.arena, dir, self.builds) catch return;
        self.builds += 1;

        var diag: ?chock_nix.Diagnostic = null;
        defer if (diag) |*d| d.deinit(self.arena);
        chock_nix.store.addRoots(
            self.arena,
            io,
            nix_store,
            self.host_env,
            link_prefix,
            built.provided.store_paths,
            &diag,
        ) catch {
            tty.print(
                .warn,
                "chock: {s} could not be held against the garbage collector. A " ++
                    "nix-collect-garbage during this session can break it.\n",
                .{installable},
            );
        };
    }
};

fn isWorkspaceFlake(workspace_root: []const u8, flake_ref: []const u8) bool {
    if (!std.mem.startsWith(u8, flake_ref, workspace_root)) return false;
    const rest = flake_ref[workspace_root.len..];
    return rest.len == 0 or rest[0] == '/';
}

/// A reference that is not this project is refused. Fetching it means fetching
/// its whole input graph, and what that graph reaches is written in a lock file
/// inside the flake, which cannot be read until the flake has been fetched, so
/// there is no moment at which the policy could be asked about those hosts.
fn foreignFlakeRefusal(
    gpa: std.mem.Allocator,
    flake_ref: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "nothing was built: {s} is not the project you are working in, and it would have to be " ++
            "fetched before it could be evaluated. This session fetches no flake but this " ++
            "project's own. Leave \"flake\" out to build an attribute of the project, or add " ++
            "what you need to its flake inputs and ask the user to run it again.",
        .{flake_ref},
    );
}

fn builtText(
    gpa: std.mem.Allocator,
    installable: []const u8,
    built: chock_nix.build.Built,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(gpa);

    try text.print(gpa, "{s} was built. It produced", .{installable});
    for (built.out_paths) |path| try text.print(gpa, " {s}", .{path});
    try text.appendSlice(gpa, ". Every call after this one can read those paths and run what " ++
        "is in their bin directories, by the program name alone. A background task or a " ++
        "subagent that was already running does not have them, and they are gone at the end " ++
        "of this session.");
    return text.toOwnedSlice(gpa);
}

fn builtRootPrefix(
    arena: std.mem.Allocator,
    dir: []const u8,
    index: usize,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}-built-{d}", .{
        dir,
        chock_nix.DevShell.root_link_name,
        index,
    });
}

fn nixBuildRefusal(
    gpa: std.mem.Allocator,
    session: *chock_nix.eval.Session,
    driver: *chock_nix.backend.Driver,
    installable: []const u8,
    expression: []const u8,
    err: anyerror,
) std.mem.Allocator.Error![]u8 {
    if (try chock_nix.build.writeRefusal(gpa, installable, err)) |said| return said;

    if (driver.lastError()) |said| return std.fmt.allocPrint(
        gpa,
        "{s} was not built, because evaluating it asked a store for something this session " ++
            "will not do: {s}. Reading the result of one build to work out another, which is " ++
            "what importing a derivation does, is refused here. Build the thing itself.",
        .{ installable, said },
    );

    if (err == error.RestrictedInPureEval) return std.fmt.allocPrint(
        gpa,
        "{s} was not built: evaluating it reads something a pure evaluation may not, such as " ++
            "a path outside the workspace, the environment, or a flake input that is not " ++
            "already on this machine. Build an attribute of the project you are working in.",
        .{installable},
    );

    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(gpa);
    try text.print(gpa, "{s} was not built, because it did not evaluate ({t}).", .{ installable, err });

    var said: std.Io.Writer.Allocating = .init(gpa);
    defer said.deinit();
    session.writeDiagnostics(&said.writer, expression) catch {};
    if (said.written().len != 0) try text.print(gpa, "\n{s}", .{said.written()});
    return text.toOwnedSlice(gpa);
}

const nix_build_is_off = "nothing was built: this session cannot build with Nix, because there " ++
    "is no nix on this machine. Do the work with what the toolchain already has.";

/// Starts a subagent: one `chock run` of its own. A child is a process and not a
/// thread, because `Sandbox.spawn` calls `fork` and `fork` carries only the
/// calling thread. The child cannot state a chain of its own, so a check it
/// performed on itself would be worth nothing. The `Io` it spawns on is backed by
/// the page allocator, because a lock another thread holds at a `fork` is one the
/// child inherits as held for ever.
const SubagentSpawner = struct {
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *const Started,
    agent_kind: []const u8,
    /// True to give the child no scratchpad at all. This exists for the reviewer
    /// agent and for nothing else: a parent may read a child's scratchpad, and
    /// the parent of a reviewer is the agent whose request is being reviewed.
    no_scratchpad: bool = false,

    fn spawner(self: *SubagentSpawner) chock_core.subagent.Spawner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.subagent.Spawner.VTable{ .prepare = prepareFn, .run = runFn };

    fn prepareFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: chock_core.subagent.Request,
    ) chock_core.subagent.Error!chock_core.subagent.Prepared {
        _ = request;
        const self: *SubagentSpawner = @ptrCast(@alignCast(ptr));

        const id = session_paths.newId(io);
        var paths = session_paths.pathsFor(allocator, self.env, self.started.project_root, &id) catch {
            tty.print(.err, "chock run: the session path for a subagent could not be built\n", .{});
            return error.ChildNotStarted;
        };
        defer paths.deinit();

        const child_session = try allocator.dupe(u8, &id);
        errdefer allocator.free(child_session);
        const log_path = try allocator.dupe(u8, paths.log);
        errdefer allocator.free(log_path);

        const scratchpad_path = if (self.no_scratchpad)
            try allocator.dupe(u8, "")
        else if (self.started.scratch_dir) |parent_dir|
            chock_core.subagent.childDir(allocator, parent_dir, child_session) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.BadChildId => return error.ChildNotStarted,
            }
        else
            try allocator.dupe(u8, "");

        return .{
            .child_session = child_session,
            .log_path = log_path,
            .scratchpad_path = scratchpad_path,
        };
    }

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: chock_core.subagent.Request,
        prepared: chock_core.subagent.Prepared,
    ) chock_core.subagent.Error!chock_core.subagent.Report {
        _ = io;
        const self: *SubagentSpawner = @ptrCast(@alignCast(ptr));

        const chain = try chock_core.subagent.Command.chainBelow(
            allocator,
            self.started.spawn_chain,
            self.agent_kind,
            request.reason,
        );
        defer allocator.free(chain);

        const argv = try chock_core.subagent.commandLine(allocator, .{
            .exe_path = self.started.exe_path,
            .project_root = self.started.project_root,
            .parent_session = self.started.session_id,
            .parent_chain = chain,
            .provider = self.started.model_alias,
            .model = self.started.model,
        }, request, prepared);
        defer chock_core.subagent.freeCommandLine(allocator, argv);

        tty.print(.plain, "chock: subagent {s} ({s}) started\n", .{ prepared.child_session, request.agent_kind });
        self.runToTheEnd(argv);

        return readChildLog(allocator, prepared, request.shape);
    }

    fn runToTheEnd(self: *SubagentSpawner, argv: []const []const u8) void {
        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = self.environ });
        defer threaded.deinit();
        const io = threaded.io();

        var child = std.process.spawn(io, .{
            .argv = argv,
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .inherit,
        }) catch |err| {
            tty.print(.err, "chock: the subagent could not be started: {t}\n", .{err});
            return;
        };
        const term = child.wait(io) catch |err| {
            tty.print(.err, "chock: the subagent could not be waited for: {t}\n", .{err});
            return;
        };
        switch (term) {
            .exited => |status| if (status != 0) {
                tty.print(.warn, "chock: the subagent exited {d}\n", .{status});
            },
            else => tty.print(.warn, "chock: the subagent did not exit normally\n", .{}),
        }
    }

    fn readChildLog(
        allocator: std.mem.Allocator,
        prepared: chock_core.subagent.Prepared,
        shape: chock_core.subagent.Shape,
    ) chock_core.subagent.Error!chock_core.subagent.Report {
        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        const path = try allocator.dupeZ(u8, prepared.log_path);
        defer allocator.free(path);

        var log = chock_proto.log.Log.open(io, path, prepared.child_session) catch {
            return .{
                .outcome = .died,
                .result = try std.fmt.allocPrint(
                    allocator,
                    "the subagent's log at {s} could not be opened, so the subagent never started",
                    .{prepared.log_path},
                ),
            };
        };
        defer log.close(io);

        var backing = chock_proto.storage.JsonLines{ .log = log };
        return chock_core.subagent.readReport(allocator, io, backing.storage(), shape);
    }
};

/// The reviewer agent: a subagent that reads one case and answers, and acts on
/// nothing. It gets no scratchpad, no tools at all, and the case with nothing of
/// the parent's conversation. `session.spawn` is appended for it before the child
/// runs, and without that a reviewer was a process the width bound could not see.
const ReviewSpawner = struct {
    child: chock_core.subagent.Spawner,
    budget: ?chock_cost.budget.Budget,
    nothing_left: bool,
    refused_by_limits: ?chock_policy.subagents.Refusal,
    locked: ?*ApprovalLock = null,

    const SpawnNotRecorded = error{NoLog} || chock_proto.storage.StorageError;

    fn reviewer(self: *ReviewSpawner) chock_broker.review.Reviewer {
        return .{
            .ptr = self,
            .vtable = &vtable,
            .kind = chock_broker.review.default_kind,
        };
    }

    const vtable = chock_broker.review.Reviewer.VTable{ .review = reviewFn };

    /// Every way this can fail is `error.ReviewNotRun`, and the broker turns each
    /// one into `review_unavailable`, which refuses: the cheapest attack on a
    /// review is to make it fail.
    fn reviewFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        case: chock_broker.review.Case,
    ) chock_broker.review.ReviewError!chock_broker.review.Report {
        const self: *ReviewSpawner = @ptrCast(@alignCast(ptr));

        if (self.refused_by_limits) |refusal| {
            tty.print(
                .warn,
                "chock: no reviewer was started for {s}: chock.zon's {s} does not allow one here\n",
                .{ case.action, refusal.limitName() },
            );
            return error.ReviewNotRun;
        }
        if (self.nothing_left) {
            tty.print(
                .warn,
                "chock: no reviewer was started for {s}: this session has spent the whole budget " ++
                    "in chock.zon, so there is nothing to pay a review with\n",
                .{case.action},
            );
            return error.ReviewNotRun;
        }

        const task = try chock_broker.review.taskFor(gpa, case);
        defer gpa.free(task);

        const request = chock_core.subagent.Request{
            .agent_kind = chock_broker.review.default_kind,
            .task = task,
            .shape = .{ .schema = &chock_broker.review.result_fields },
            .reason = case.action,
            .budget = self.budget,
        };

        const prepared = self.child.prepare(gpa, io, request) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ChildNotStarted => return error.ReviewNotRun,
        };
        defer chock_core.subagent.freePrepared(gpa, prepared);

        // Before the child runs, so a crash between the two still leaves proof
        // that this child was asked for. A spawn that cannot be written starts
        // nothing: a child the width bound cannot see is worse than a review that
        // did not run.
        self.recordSpawn(gpa, io, request, prepared) catch {
            tty.print(
                .warn,
                "chock: no reviewer was started for {s}: the spawn could not be written to this " ++
                    "session's log, and a child nothing counts is a child that does not run\n",
                .{case.action},
            );
            return error.ReviewNotRun;
        };

        const report = self.child.run(gpa, io, request, prepared) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ChildNotStarted => return error.ReviewNotRun,
        };
        defer chock_core.subagent.freeReport(gpa, report);

        if (report.outcome != .finished) {
            tty.print(
                .warn,
                "chock: the reviewer for {s} ended {s}: {s}\n",
                .{ case.action, report.outcome.wireName(), report.result },
            );
            return error.ReviewNotRun;
        }

        return chock_broker.review.readAnswer(gpa, report.result);
    }

    fn recordSpawn(
        self: *ReviewSpawner,
        gpa: std.mem.Allocator,
        io: std.Io,
        request: chock_core.subagent.Request,
        prepared: chock_core.subagent.Prepared,
    ) SpawnNotRecorded!void {
        const handle = self.locked orelse return error.NoLog;
        _ = try handle.append(gpa, io, .{ .session_spawn = .{
            .child_session = prepared.child_session,
            .child_agent_kind = request.agent_kind,
            .reason = request.reason,
            .budget_max_cost = if (self.budget) |one| one.max_cost else 0,
            .budget_currency = if (self.budget) |one| one.currency else "",
        } }, std.Io.Timestamp.now(io, .real).toMilliseconds());
    }
};

/// Nothing here starts anything. The spawn limits and what is left of the budget
/// are read from the session's own log, so a session that was resumed counts the
/// children it really has.
fn reviewerFor(
    child: chock_core.subagent.Spawner,
    started: *const Started,
    session: anytype,
) ReviewSpawner {
    const bounds = reviewBounds(
        started.subagents,
        .{ .depth = started.spawn_chain.len + 1, .width = session.children.items.len },
        started.budget,
        session.spend,
        session.children.items,
    );

    return .{
        .child = child,
        .budget = bounds.budget,
        .nothing_left = bounds.nothing_left,
        .refused_by_limits = bounds.refused_by_limits,
    };
}

fn reviewChild(
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *const Started,
    options: Options,
) SubagentSpawner {
    return .{
        .gpa = gpa,
        .environ = environ,
        .env = env,
        .started = started,
        .agent_kind = options.agent_kind,
        .no_scratchpad = true,
    };
}

const ReviewBounds = struct {
    budget: ?chock_cost.budget.Budget,
    nothing_left: bool,
    refused_by_limits: ?chock_policy.subagents.Refusal,
};

fn reviewBounds(
    limits: chock_policy.subagents.Limits,
    standing: chock_policy.subagents.Standing,
    cap: ?chock_cost.budget.Budget,
    spend: chock_proto.state.Spend,
    children: []const chock_proto.state.Child,
) ReviewBounds {
    const committed = chock_core.subagent.committedToChildren(children, cap);
    return .{
        .budget = chock_core.subagent.budgetSlice(cap, spend, committed, 1),
        .nothing_left = chock_core.subagent.nothingLeft(cap, spend, committed),
        .refused_by_limits = chock_policy.subagents.check(limits, standing),
    };
}

const max_ancestor_sessions: usize = chock_policy.subagents.max_settable;

/// A promise a parent made has to reach its children, or an agent that promises
/// not to apply its work can start a subagent to apply it. The promises come out
/// of the ancestors' own logs and never off a command line, where a parent that
/// passed none would be a parent widening its child.
fn promisesFor(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    parent_session: []const u8,
    session: anytype,
) std.mem.Allocator.Error![]const chock_policy.ratchet.Restriction {
    var out: std.ArrayList(chock_policy.ratchet.Restriction) = .empty;
    try appendPromises(arena, &out, session.self_policy.restrictions.items);

    var next: []const u8 = parent_session;
    var walked: usize = 0;
    while (next.len != 0) {
        if (!session_paths.isValidId(next)) {
            tty.print(
                .warn,
                "chock run: {s} is not a session identifier, so the promises of the sessions " ++
                    "above this one were not read.\n",
                .{next},
            );
            break;
        }
        walked += 1;
        if (walked > max_ancestor_sessions) {
            tty.print(
                .warn,
                "chock run: the sessions above this one go more than {d} deep, so the ones " ++
                    "above that were not read.\n",
                .{max_ancestor_sessions},
            );
            break;
        }

        var ancestor = chock_proto.state.Session.init(gpa);
        defer ancestor.deinit();
        const whole = foldSessionById(gpa, io, dir, next, &ancestor);
        try appendPromises(arena, &out, ancestor.self_policy.restrictions.items);
        if (!whole) {
            tty.print(
                .warn,
                "chock run: the log of session {s} could not be read to its end, so a promise " ++
                    "it or the sessions above it made may not be applied here.\n",
                .{next},
            );
            break;
        }
        next = try arena.dupe(u8, ancestor.parent_session);
    }
    return out.toOwnedSlice(arena);
}

fn appendPromises(
    arena: std.mem.Allocator,
    out: *std.ArrayList(chock_policy.ratchet.Restriction),
    folded: []const chock_proto.event.SelfRestriction,
) std.mem.Allocator.Error!void {
    const read = try chock_core.self_policy.restrictionsFrom(arena, folded);
    defer arena.free(read);
    for (read) |one| {
        try out.append(arena, .{
            .action = try arena.dupe(u8, one.action),
            .ceiling = one.ceiling,
            .reason = try arena.dupe(u8, one.reason),
        });
    }
}

/// The file is checked before the log is opened: `chock_proto.log.Log.open`
/// creates the file and writes a header into it when there is none, so asking
/// about a session that never existed would bring one into being. `session`
/// still holds everything that was read.
fn foldSessionById(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    session: *chock_proto.state.Session,
) bool {
    std.debug.assert(session_paths.isValidId(id));
    const path = std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir, id }, 0) catch return false;
    defer gpa.free(path);
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;

    const log = chock_proto.log.Log.open(io, path, id) catch return false;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var replay = store.replay(gpa, io, 0) catch return false;
    defer replay.deinit();
    while (replay.next(io) catch return false) |parsed| {
        defer parsed.deinit();
        session.apply(parsed.value) catch return false;
    }
    return true;
}

fn foldSession(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    session: *chock_proto.state.Session,
) void {
    var replay = storage.replay(gpa, io, 0) catch return;
    defer replay.deinit();
    while (replay.next(io) catch null) |parsed| {
        defer parsed.deinit();
        session.apply(parsed.value) catch return;
    }
}

/// A fold split across many calls reaches the same state a single fold of the
/// whole log would, because `state.Session.apply` only ever adds or overwrites one
/// field and never looks back. A line that will not decode stops the fold and
/// leaves `at` unmoved; a torn tail moves `at` to the tear's own start.
fn foldSessionSince(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    session: anytype,
    at: *u64,
) void {
    var replay = storage.replay(gpa, io, at.*) catch return;
    defer replay.deinit();
    while (true) {
        const parsed = replay.next(io) catch return;
        const envelope = parsed orelse break;
        defer envelope.deinit();
        session.apply(envelope.value) catch return;
        at.* = replay.at();
    }
    at.* = replay.at();
}

/// One path for every session, because a fresh log folds to nothing: none of the
/// events phase 1 wrote is a row. A log that cannot be read is said out loud and
/// does not refuse the session: this only decides what is on screen.
fn replayInto(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    screen: *ui.Ui,
) void {
    var replay = storage.replay(gpa, io, 0) catch |err| {
        tty.print(
            .warn,
            "chock: this session's log could not be read back ({s}), so the display opens " ++
                "empty. The conversation itself is unaffected.\n",
            .{@errorName(err)},
        );
        return;
    };
    defer replay.deinit();

    while (true) {
        const parsed = replay.next(io) catch |err| {
            tty.print(
                .warn,
                "chock: this session's log stops being readable ({s}), so the display shows " ++
                    "only what came before that point.\n",
                .{@errorName(err)},
            );
            return;
        } orelse {
            if (replay.truncated()) tty.print(
                .warn,
                "chock: this session's log ends part way through a line, so the last event " ++
                    "before it is not on the display.\n",
                .{},
            );
            return;
        };
        defer parsed.deinit();
        screen.replay(parsed.value.id, parsed.value.event);
    }
}

fn runSession(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *Started,
    options: Options,
    take_up: *?[]const u8,
    shipped: *ShippingReport,
) !Exit {
    var http = switch (started.adapter) {
        .openai_compatible => chock_provider.Client.HttpClient.init(gpa, io, started.base_url, started.credential.token),
        .anthropic => chock_provider.Client.HttpClient.initAnthropic(gpa, io, started.base_url, started.credential.token),
    };
    defer http.deinit();

    var supervisor_audit: sandbox.Sandbox.SupervisorAudit = .{};
    started.sandbox_config.supervisor_audit = &supervisor_audit;
    defer started.sandbox_config.supervisor_audit = null;
    defer logSupervisorAudit(gpa, io, started.storage, &supervisor_audit);

    // Off unless a policy asks: the sandbox watches nothing until
    // `Config.seccomp_options.traps` names a call.
    var syscall_audit: sandbox.Sandbox.SyscallAudit = .{};
    started.sandbox_config.syscall_audit = &syscall_audit;
    defer started.sandbox_config.syscall_audit = null;
    defer logSyscallAudit(gpa, io, started.storage, &syscall_audit);

    var context = chock_core.tools.Context{
        .memory_dir = started.memory_dir,
        .cache_dir = started.cache_dir,
        .scratch_dir = started.scratch_dir,
        .workspace_dir = started.workspace.workPath(),
        .session_id = started.session_id,
    };
    context.store_paths = started.toolchain.store_paths;
    context.toolchain_mounts = started.toolchain.mounts;
    context.provisioning = started.provisioning != null;
    context.role = agentRole(options);

    // The page allocator, and never `gpa`. A task's own thread allocates from
    // this beside a thread that may be inside `Sandbox.spawn`, and `fork` carries
    // only the calling thread.
    var table: ?chock_core.tasks.Table = if (started.tasks_dir) |dir| .{
        .gpa = std.heap.page_allocator,
        .dir = dir,
        .runner = chock_core.tools.backgroundRunner(),
    } else null;
    // Ends every task still running, then waits for it: a thread of this table
    // writes into a directory phase 3 is about to remove. Waiting alone is not an
    // option either, because a session that is over must not sit for half an hour
    // on a build whose output nobody will read.
    defer if (table) |*one| {
        chock_core.tools.cancelRunningTool();
        one.deinit();
    };
    if (table) |*one| context.tasks = one;

    var tool_runner = chock_core.Loop.SandboxToolRunner{
        .env = started.tool_env,
        .sandbox_config = started.sandbox_config,
        .context = context,
    };

    var git_aware = GitToolRunner{ .inner = tool_runner.runner() };

    var language_server = chock_core.lsp.Session{};

    var server_helper = chock_core.helper.Helper.init(std.heap.page_allocator);
    defer server_helper.deinit(io);

    var server_driver: ?chock_core.lsp_driver.Driver = null;
    defer if (server_driver) |*one| one.deinit();

    var server_arena = std.heap.ArenaAllocator.init(gpa);
    defer server_arena.deinit();

    const server_settings: ?chock_core.lsp_driver.Settings = if (started.language_server) |settings|
        (if (try languageServerPermitted(
            gpa,
            started.policy,
            started.spawn_chain,
            options.agent_kind,
            started.model,
            settings.command,
        )) settings else null)
    else
        null;

    if (server_settings) |settings| {
        const prepared = blk: {
            const with_store = chock_core.tools.withStore(
                server_arena.allocator(),
                io,
                started.sandbox_config,
                context.store_paths,
                context.toolchain_mounts,
            ) catch break :blk null;
            break :blk chock_core.tools.prepare(
                server_arena.allocator(),
                io,
                started.tool_env,
                with_store,
                settings.command,
                &.{},
                &.{},
            ) catch |err| {
                tty.print(
                    .warn,
                    "chock: the language server {s} could not be prepared ({t}), so nothing " ++
                        "checks this session's edits.\n",
                    .{ settings.command[0], err },
                );
                break :blk null;
            };
        };

        if (prepared) |ready| {
            server_driver = .{
                .gpa = gpa,
                .process = &server_helper,
                .request = .{ .config = ready.config, .argv = ready.argv },
                .work_root = started.workspace.workPath(),
                .sandbox_root = started.sandbox_config.cwd,
            };
            language_server = .{
                .program = settings.command[0],
                .suffixes = settings.suffixes,
                .server = server_driver.?.server(),
            };
        }
    }

    var diagnosing = DiagnosticToolRunner{
        .inner = git_aware.runner(),
        .session = &language_server,
    };

    var provision_arena = std.heap.ArenaAllocator.init(gpa);
    defer provision_arena.deinit();

    var nix_eval = NixEvalToolRunner{
        .inner = diagnosing.runner(),
        .settings = .{
            .workspace_root = started.workspace.workPath(),
            .caps = started.nix_caps,
        },
    };

    var session_mounts = SessionMounts{
        .arena = provision_arena.allocator(),
        .context = &tool_runner.context,
        .tool_env = started.tool_env,
    };
    try session_mounts.start(context.store_paths);

    var nix_build = NixBuildToolRunner{
        .inner = nix_eval.runner(),
        .settings = started.nix_build,
        .arena = provision_arena.allocator(),
        .host_env = env,
        .environ = environ,
        .mounts = &session_mounts,
    };

    var provisioning = ProvisionToolRunner{
        .inner = nix_build.runner(),
        .settings = started.provisioning,
        .arena = provision_arena.allocator(),
        .host_env = env,
        .environ = environ,
        .mounts = &session_mounts,
    };

    // Started here and not in phase 1, unlike every other block of `chock.zon`. A
    // server has to be asked what tools it has before the model can be offered
    // one, and asking means a `fork`, which phase 1 cannot do beside the threads
    // that build the workspace.
    var mcp_state = McpState.init(gpa);
    defer mcp_state.deinit(io);

    const mcp_definitions, const mcp_prompt = try startMcp(
        gpa,
        io,
        started,
        options,
        &context,
        &mcp_state,
    );

    var plugin_state = PluginState.init(gpa);
    defer plugin_state.deinit(io);

    const tool_definitions, const system_prompt = try startPlugins(
        gpa,
        io,
        started,
        options,
        &context,
        &plugin_state,
        &mcp_state.session,
        mcp_definitions,
        mcp_prompt,
    );

    var mcp_aware = McpToolRunner{
        .inner = provisioning.runner(),
        .state = &mcp_state,
    };

    var plugin_aware = PluginToolRunner{
        .inner = mcp_aware.runner(),
        .state = &plugin_state,
    };

    var subagent_spawner = SubagentSpawner{
        .gpa = gpa,
        .environ = environ,
        .env = env,
        .started = started,
        .agent_kind = options.agent_kind,
    };

    var children = chock_core.subagent.Table{
        .gpa = std.heap.page_allocator,
        .spawner = subagent_spawner.spawner(),
    };
    // Waits, and does not cancel. A child holds a log of its own that a person
    // reads afterwards, and a child killed between two turns leaves one with no
    // `session.end`, which its parent then reads as a child that died.
    defer children.deinit();

    defer {
        if (children.takeLost()) |lost| tty.print(.warn, "chock: {f}\n", .{lost});
        if (table) |*one| {
            if (one.takeLost()) |lost| tty.print(.warn, "chock: {f}\n", .{lost});
        }
    }

    var printer = Printer.init(gpa, io);
    printer.paint = tty.stdoutPainter();
    defer printer.deinit();

    var screen: ?*ui.Ui = null;
    defer if (screen) |one| one.deinit();

    // Before the display: two of the three probes fork, and a fork taken after
    // `Ui.start` would be a fork of a process holding a terminal in raw mode.
    const layer_witness = witnessLayers(gpa, sandbox.Sandbox.guarantees);

    if (options.display) |wanted| {
        screen = ui.Ui.start(gpa, io, env, wanted.attach) catch |err| open_failed: {
            tty.print(
                .warn,
                "chock: the display could not start ({s}), printing plainly instead.\n",
                .{@errorName(err)},
            );
            break :open_failed null;
        };
    }

    const layers = sandboxLayers(
        sandbox.Sandbox.guarantees,
        layer_witness,
        started.sandbox_config.network,
        switch (started.workspace.kind) {
            .worktree => "worktree",
            .overlay => "overlay",
        },
    );

    if (screen) |one| {
        printer.paint = .off;
        printer.out = .{ .buffer = .{ .gpa = gpa, .bytes = &one.transcript } };
        one.wrap(printer.observer());
        if (table) |*one_table| one.tasks = one_table;
        one.describe(.{
            .project = std.fs.path.basename(started.project_root),
            .workspace = switch (started.workspace.kind) {
                .worktree => "worktree",
                .overlay => "overlay",
            },
            .model = started.model,
            .provider = started.model_alias,
            .layers = &layers,
        });
        one.resumable(started.paths.dir, started.session_id);
        replayInto(gpa, io, started.storage, one);
        if (started.apply_mode.mode == null) one.note(
            bounded_mode_fmt,
            .{
                started.apply_mode.asked_for.wireName(),
                started.apply_mode.decision,
                chock_policy.apply.integrate_action,
            },
        );
        if (options.display.?.first_message.len != 0) one.prime(options.display.?.first_message);
    }

    const wall = clock.Real{
        .io = io,
        .offset_minutes = clock.localOffsetMinutes(
            gpa,
            io,
            std.Io.Timestamp.now(io, .real).toMilliseconds(),
        ),
    };

    // A signal does not run a deferred append, so a killed session left a log
    // that stops mid conversation with nothing saying why. Installed here,
    // because before the loop exists there is nothing reading the flag.
    interrupt.install();

    if (started.handovers) |endpoint| handover.arm(endpoint);
    defer handover.disarm();

    var session_arbiter = SessionArbiter{
        .gpa = gpa,
        .environ = environ,
        .env = env,
        .started = started,
        .options = options,
        .screen = screen,
    };
    defer session_arbiter.deinit();

    const tool_network_chain = try policyChain(gpa, started, options);
    defer gpa.free(tool_network_chain);

    var tool_network = ToolNetwork{
        .gpa = gpa,
        .io = io,
        .started = started,
        .screen = screen,
        .session = .init(gpa),
        .network = .{
            .gpa = gpa,
            .io = io,
            .table = started.policy,
            .chain = tool_network_chain,
            .agent_kind = options.agent_kind,
            .model = started.model,
            .tool = "",
            .transport = undefined,
        },
    };
    tool_network.network.transport = tool_network.transport.transport();
    defer tool_network.deinit();

    if (started.sandbox_config.network == .filtered) {
        tool_runner.context.net = tool_network.seam();
    }
    tool_runner.context.approval_wait_ns = &tool_network.approval_wait_ns;

    mcp_state.session.asker = .{ .arbiter = session_arbiter.arbiter() };
    plugin_state.session.asker = .{ .arbiter = session_arbiter.arbiter() };

    git_aware.asker = .{ .arbiter = session_arbiter.arbiter() };

    nix_build.asker = .{ .arbiter = session_arbiter.arbiter() };
    nix_build.rule = .{
        .policy = started.policy,
        .chain = try policyChain(provision_arena.allocator(), started, options),
        .agent_kind = options.agent_kind,
        .model = started.model,
    };

    // A directory of its own, and never the session's `.ctl`: an agent that could
    // reach the approval socket could answer its own questions.
    const credential_dir = try std.fmt.allocPrint(
        gpa,
        "{s}/{s}.cred",
        .{ started.paths.dir, started.session_id },
    );
    defer gpa.free(credential_dir);
    defer std.Io.Dir.cwd().deleteTree(io, credential_dir) catch {};

    const credential_helper = std.Io.Dir.realPathFileAlloc(
        .cwd(),
        io,
        started.exe_path,
        gpa,
    ) catch try gpa.dupe(u8, "");
    defer gpa.free(credential_helper);

    const credential_chain = try policyChain(gpa, started, options);
    defer gpa.free(credential_chain);

    var git_credentials = GitCredentials{
        .gpa = gpa,
        .io = io,
        .dir = credential_dir,
        .helper = credential_helper,
        .secrets = .{
            .io = io,
            .screen = screen,
            .at_terminal = approval.hasTerminal(io) and screen == null,
        },
        .asker = .{
            .table = started.policy,
            .chain = credential_chain,
            .agent_kind = options.agent_kind,
            .model = started.model,
        },
        .host_agent = env.get(chock_broker.agentproxy.env_socket) orelse "",
        // `@constCast` is sound here: the slice was allocated mutable in phase
        // 1's arena, and this is the one owner that writes it, from one thread.
        .live = if (started.redact.secrets.len != 0)
            &@constCast(started.redact.secrets)[started.redact.secrets.len - 1]
        else
            null,
    };
    defer git_credentials.disarm(gpa, io);

    git_aware.credentials = &git_credentials;
    git_aware.project_root = started.project_root;
    tool_runner.context.credentials = git_credentials.seam();

    var give_locked = GiveLockedToAll{
        .network = &tool_network,
        .mcp = &mcp_state.session,
        .plugins = &plugin_state.session,
        .git = &git_aware,
        .nix = &nix_build,
    };

    var session_handback = SessionHandback{
        .environ = environ,
        .env = env,
        .started = started,
        .options = options,
        .screen = screen,
    };

    var fetch_arena = std.heap.ArenaAllocator.init(gpa);
    defer fetch_arena.deinit();

    var fetcher = SessionFetcher{
        .gpa = gpa,
        .session = .{
            .gpa = gpa,
            .table = started.policy,
            .chain = try policyChain(fetch_arena.allocator(), started, options),
            .agent_kind = options.agent_kind,
            .model = started.model,
            .tool = chock_core.Loop.fetch_tool_name,
            .env = env,
        },
        .ancestors = ancestors: {
            var above = chock_proto.state.Session.init(gpa);
            defer above.deinit();
            break :ancestors promisesFor(
                gpa,
                fetch_arena.allocator(),
                io,
                started.paths.dir,
                options.parent_session,
                &above,
            ) catch &.{};
        },
    };
    defer fetcher.deinit();

    // Only when both halves are named. A block with no kind or no base url is
    // not an engine, and the seam stays null so the tool says so.
    var searcher: ?SessionSearcher = if (started.search.kind) |kind| about: {
        const base = started.search.base_url orelse break :about null;
        break :about SessionSearcher{ .session = .{
            .kind = kind,
            .base_url = base,
            .provider = started.search.provider,
            .credential = started.search_credential,
            .clean = chock_core.mcp.textForModel,
        } };
    } else null;

    var sinks = Sinks{};
    defer sinks.close(io);
    sinks.open(options, started.audit_sinks, started.session_id);

    var exporter = Exporter{
        .gpa = gpa,
        .io = io,
        .storage = started.storage,
        .inner = if (screen) |one| one.observer() else printer.observer(),
        .sinks = sinks.slice(),
    };
    defer if (sinks.count != 0) exporter.finish(shipped);

    if (sinks.anyRequired()) exporter.probe();

    var question_console = QuestionConsole{};
    var question_prompt = chock_core.ask.Prompt{
        .console = question_console.console(),
        .at_terminal = approval.hasTerminal(io) and screen == null,
        .stop = interrupt.requested,
    };
    var display_asker = DisplayAsker{
        .screen = screen orelse undefined,
        .agent_kind = options.agent_kind,
    };

    var pump = DisplayPump{ .screen = screen orelse undefined };
    if (screen != null) {
        http.idle = pump.providerIdle();
        tool_runner.context.idle = pump.coreIdle();
    }

    var deps = chock_core.Loop.Deps{
        .client = http.client(),
        .storage = started.storage,
        .tool_runner = plugin_aware.runner(),
        .give_locked = give_locked.giveLocked(),
        .tool_definitions = tool_definitions,
        .model = started.model,
        .model_alias = started.model_alias,
        .agent_kind = options.agent_kind,
        .role = agentRole(options),
        .system_prompt = system_prompt,
        .observer = if (sinks.count != 0) exporter.observer() else exporter.inner,
        .canceled = interrupt.requested,
        // Only at a turn boundary, which is why this is not `canceled`. A session
        // that stopped between two tool calls of one turn leaves an assistant
        // message whose `tool_use` parts have no matching results.
        .handover = handover.requested,
        .budget = started.budget,
        .billing = started.billing,
        .subagents = started.subagents,
        .spawn_chain = started.spawn_chain,
        .config = started.session_config,
        .parent_session = options.parent_session,
        .spawner = subagent_spawner.spawner(),
        .children = &children,
        .compaction = .{ .context_limit_tokens = started.context_tokens },
        .notices = .{
            .enabled = !options.no_notices,
            .clock = wall.clock(),
        },
        .uncommitted_files = started.uncommitted_files,
        .tasks = if (table) |*one| one else null,
        .arbiter = session_arbiter.arbiter(),
        .project_root = started.sandbox_config.cwd,
        .store_closure = started.toolchain.store_paths,
        .handback = session_handback.handback(),
        .fetcher = fetcher.fetcher(),
        .searcher = if (searcher) |*one| one.searcher() else null,
        .asker = if (screen != null) display_asker.asker() else question_prompt.asker(),
        .redact = started.redact,
    };
    deps.max_turns = options.max_turns;

    var turns: usize = 0;
    while (true) {
        if (screen) |one| {
            switch (try one.askForMessage(gpa)) {
                .done => break,
                .message => |next| {
                    defer gpa.free(next);
                    try appendUserMessage(gpa, io, started.storage, next);
                },
                .take_up => |id| {
                    take_up.* = id;
                    break;
                },
            }
        }

        try chock_core.Loop.run(gpa, io, deps);
        turns += 1;
        if (screen == null) break;

        if (!keepAsking(try finalExit(gpa, io, started.storage), interrupt.requested())) break;
    }

    if (turns == 0) return .usage;

    return try finalExit(gpa, io, started.storage);
}

fn keepAsking(ending: Exit, interrupted: bool) bool {
    if (interrupted) return false;
    return ending == .finished;
}

fn finalExit(gpa: std.mem.Allocator, io: std.Io, storage: chock_proto.storage.Storage) !Exit {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();

    var last: Exit = .faulted;
    var saw_end = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_end) continue;
        const ended = parsed.value.event.session_end;
        last = exitFor(ended.reason);
        saw_end = true;
    }
    if (!saw_end) return .faulted;
    return last;
}

const max_sinks: usize = chock_policy.org.max_sinks + 2;

const ShippingReport = struct {
    entries: [max_sinks]Entry = undefined,
    count: usize = 0,

    const Entry = struct {
        name: []const u8,
        health: chock_proto.ship.Health,
        required: bool = false,

        /// Whether this sink holds less than the whole of the session's log, and
        /// will never hold the rest. A sink that was down and came back is not a
        /// gap: the log on disk is the queue.
        fn gap(self: Entry) bool {
            return self.health.stalled_at != null or self.health.refused != 0;
        }
    };

    fn add(self: *ShippingReport, one: Entry) void {
        if (self.count >= self.entries.len) return;
        self.entries[self.count] = one;
        self.count += 1;
    }

    fn slice(self: *const ShippingReport) []const Entry {
        return self.entries[0..self.count];
    }

    fn requiredGap(self: *const ShippingReport) bool {
        for (self.slice()) |one| {
            if (one.required and one.gap()) return true;
        }
        return false;
    }
};

fn reportShipping(report: *const ShippingReport) void {
    for (report.slice()) |one| {
        if (!one.health.wantsSaying()) {
            tty.print(.plain, "chock run: {d} lines of this session's log reached {s}{s}.\n", .{
                one.health.delivered,
                one.name,
                if (one.required) ", which this installation requires" else "",
            });
            continue;
        }
        if (!one.required) {
            tty.print(.warn, "chock run: the audit sink {s}: {f}\n", .{ one.name, &one.health });
            continue;
        }
        tty.print(
            .warn,
            "chock run: {s} is an audit sink this installation's org policy requires: {f}\n",
            .{ one.name, &one.health },
        );
        if (!one.gap()) continue;
        tty.print(
            .warn,
            "chock run: part of this session's record is on this machine and nowhere else. The " ++
                "session itself is not a failure, because a session must not fail because an " ++
                "audit sink is down. The record is, and a session that otherwise finished " ++
                "reports it as exit {d}.\n",
            .{Exit.audit_gap.code()},
        );
    }
}

/// Never moved after `open`: each `Sending` holds a `Sink` pointing into this
/// struct's own arrays. Every name here is the run's own arena, because a
/// `ShippingReport` borrows them and is read in phase 3.
const Sinks = struct {
    drops: [max_sinks]chock_proto.ship.FileDrop = @splat(.{ .path = "" }),
    syslogs: [max_sinks]chock_proto.ship.Syslog = @splat(.{ .path = "" }),
    drop_count: usize = 0,
    syslog_count: usize = 0,
    sending: [max_sinks]Exporter.Sending = undefined,
    count: usize = 0,

    fn open(self: *Sinks, options: Options, planned: []const PlannedSink, session_id: []const u8) void {
        const continued = options.adopt or options.continue_newest or options.session != null;
        for (planned) |one| {
            if (self.count >= self.sending.len) return;
            const sink = switch (one.kind) {
                .directory => made: {
                    if (self.drop_count >= self.drops.len) return;
                    const slot = &self.drops[self.drop_count];
                    self.drop_count += 1;
                    slot.path = one.path;
                    break :made slot.sink();
                },
                .syslog => made: {
                    if (self.syslog_count >= self.syslogs.len) return;
                    const slot = &self.syslogs[self.syslog_count];
                    self.syslog_count += 1;
                    slot.path = one.path;
                    break :made slot.sink();
                },
            };
            self.sending[self.count] = .{
                .name = one.path,
                .required = one.required,
                .shipper = .{ .sink = sink, .session = session_id, .continued = continued },
            };
            self.count += 1;
        }
    }

    fn slice(self: *Sinks) []Exporter.Sending {
        return self.sending[0..self.count];
    }

    fn anyRequired(self: *const Sinks) bool {
        for (self.sending[0..self.count]) |one| {
            if (one.required) return true;
        }
        return false;
    }

    fn close(self: *Sinks, io: std.Io) void {
        for (self.syslogs[0..self.syslog_count]) |*one| one.close();
        for (self.drops[0..self.drop_count]) |*one| one.close(io);
    }
};

const Exporter = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    inner: chock_core.Loop.Observer,
    sinks: []Sending,
    said: bool = false,

    const Sending = struct {
        name: []const u8,
        shipper: chock_proto.ship.Shipper,
        required: bool = false,
    };

    fn observer(self: *Exporter) chock_core.Loop.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };

    fn onEventFn(ptr: *anyopaque, id: u64, ev: chock_proto.event.Event) void {
        const self: *Exporter = @ptrCast(@alignCast(ptr));
        self.inner.onEvent(id, ev);
        self.push();
    }

    fn onPieceFn(ptr: *anyopaque, piece: chock_core.Loop.Piece) void {
        const self: *Exporter = @ptrCast(@alignCast(ptr));
        self.inner.onPiece(piece);
    }

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        const self: *Exporter = @ptrCast(@alignCast(ptr));
        self.inner.onNotice(text);
    }

    fn push(self: *Exporter) void {
        for (self.sinks) |*one| {
            const before = one.shipper.health.faults;
            one.shipper.push(self.gpa, self.io, self.storage);
            if (one.shipper.health.faults == before or self.said) continue;
            self.said = true;
            self.sayFault(one.*);
        }
    }

    fn sayFault(self: *Exporter, one: Sending) void {
        var buffer: [512]u8 = undefined;
        const why = @errorName(one.shipper.health.first_fault orelse error.Unexpected);
        const text = if (one.required) std.fmt.bufPrint(
            &buffer,
            "{s} could not be reached ({s}). This installation's org policy requires that sink. " ++
                "The session carries on, because it must not fail because an audit sink is down, " ++
                "and the log keeps every line the sink missed until it comes back.",
            .{ one.name, why },
        ) catch return else std.fmt.bufPrint(
            &buffer,
            "the audit sink {s} could not be reached ({s}). The session carries on, and the log " ++
                "keeps every line the sink missed until it comes back.",
            .{ one.name, why },
        ) catch return;
        self.inner.onNotice(text);
    }

    fn probe(self: *Exporter) void {
        self.push();
    }

    fn finish(self: *Exporter, report: *ShippingReport) void {
        for (self.sinks) |*one| {
            one.shipper.finish(self.gpa, self.io, self.storage);
            report.add(.{
                .name = one.name,
                .health = one.shipper.health,
                .required = one.required,
            });
        }
    }
};

const Printer = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    out: Out = .stdout,
    paint: tty.Painter = .off,
    streamed: usize = 0,
    plan: chock_proto.state.Plan = .{},
    plan_arena: ?std.heap.ArenaAllocator = null,

    const Out = union(enum) {
        stdout,
        buffer: struct { gpa: std.mem.Allocator, bytes: *std.ArrayList(u8) },
    };

    fn init(gpa: std.mem.Allocator, io: std.Io) Printer {
        return .{ .gpa = gpa, .io = io };
    }

    fn deinit(self: *Printer) void {
        if (self.plan_arena) |*one| one.deinit();
        self.plan_arena = null;
        self.plan = .{};
    }

    fn observer(self: *Printer) chock_core.Loop.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        const self: *Printer = @ptrCast(@alignCast(ptr));
        defer self.flush();
        self.open(.dim);
        self.write("\nchock: ");
        self.write(text);
        self.write("\n");
        self.close(.dim);
    }

    fn onPieceFn(ptr: *anyopaque, piece: chock_core.Loop.Piece) void {
        const self: *Printer = @ptrCast(@alignCast(ptr));
        defer self.flush();
        switch (piece) {
            .text => |text| {
                if (text.len == 0) return;
                self.write(text);
                self.streamed += 1;
            },
            .reasoning => {},
        }
    }

    fn onEventFn(ptr: *anyopaque, id: u64, ev: chock_proto.event.Event) void {
        _ = id;
        const self: *Printer = @ptrCast(@alignCast(ptr));
        defer self.flush();
        switch (ev) {
            .message => |m| {
                if (m.role == .system) {
                    self.open(.dim);
                    for (m.content) |part| {
                        if (part != .text or part.text.len == 0) continue;
                        self.write("\n");
                        self.write(part.text);
                    }
                    self.close(.dim);
                    return;
                }
                if (m.role != .assistant) return;
                const streamed = self.streamed;
                self.streamed = 0;
                var wrote_anything = streamed != 0;
                for (m.content) |part| switch (part) {
                    .text => |text| {
                        if (text.len == 0) continue;
                        if (streamed != 0) continue;
                        self.write(text);
                        wrote_anything = true;
                    },
                    .reasoning => {},
                    .tool_use, .tool_result, .image, .unknown => {},
                };
                if (wrote_anything) self.write("\n");
            },
            .tool_call => |call| {
                self.open(.dim);
                defer self.close(.dim);
                self.write("\n$ ");
                self.write(call.tool);
                self.write(" ");
                self.write(call.arguments);
                self.write("\n");
            },
            .tool_result => |result| {
                if (result.note.len != 0) {
                    self.open(.dim);
                    self.write("chock: ");
                    self.write(result.note);
                    self.write("\n");
                    self.close(.dim);
                }
                const rank: tty.Rank = if (result.is_error) .err else .plain;
                self.open(rank);
                defer self.close(rank);
                if (result.is_error) self.write("! ");
                const shown = result.output[0..@min(result.output.len, shown_result_bytes)];
                self.write(shown);
                if (shown.len != result.output.len) self.write("\n[...the whole result is in the log]");
                self.write("\n");
            },
            .compaction => |folded| {
                const rank: tty.Rank = if (folded.stand_in_reason.len != 0) .warn else .dim;
                self.open(rank);
                defer self.close(rank);
                self.write("\nchock: the context was folded into a summary");
                if (folded.model_alias.len != 0) {
                    self.write(", written by ");
                    self.write(folded.model_alias);
                }
                if (folded.stand_in_reason.len != 0) {
                    self.write(", written by the harness, because ");
                    self.write(folded.stand_in_reason);
                }
                self.write(". Every turn is still in the session log.\n");
            },
            .task_complete => |done| {
                self.open(.dim);
                defer self.close(.dim);
                self.write("\nchock: the background task ");
                self.write(done.task_id);
                self.write(" finished, ");
                self.write(done.status.wireName());
                var code_buffer: [16]u8 = undefined;
                self.write(std.fmt.bufPrint(&code_buffer, " {d}", .{done.code}) catch "");
                self.write(": ");
                self.write(done.command);
                self.write("\n");
            },
            .plan_update => |update| self.foldPlan(update),
            .policy_self => |update| {
                self.open(.dim);
                defer self.close(.dim);
                for (update.restrictions) |one| {
                    self.write("\nchock: the agent promised ");
                    self.write(one.action);
                    self.write(" at most ");
                    self.write(one.ceiling.wireName());
                    if (one.reason.len != 0) {
                        self.write(": ");
                        self.write(one.reason);
                    }
                    self.write("\n");
                }
            },
            .session_end => |ended| {
                const rank: tty.Rank = if (ended.reason == .finished) .dim else .warn;
                self.open(rank);
                defer self.close(rank);
                self.write("\nchock: session ended, ");
                self.write(ended.reason.wireName());
                if (ended.detail.len != 0) {
                    self.write(": ");
                    self.write(ended.detail);
                }
                self.write("\n");
            },
            else => {},
        }
    }

    /// One event carries only the steps that moved, and a task list has one
    /// current state. The abandoned count is written only while it is not zero,
    /// or `1 of 4 done` reads as three left.
    fn foldPlan(self: *Printer, update: chock_proto.event.PlanUpdate) void {
        var gave_up: [max_said_steps]usize = undefined;
        var count: usize = 0;
        for (update.steps, 0..) |step, at| {
            if (!ui.isStatus(step.status, .abandoned)) continue;
            if (self.plan.find(step.id)) |had| {
                if (ui.isStatus(had.status, .abandoned)) continue;
            }
            if (count == gave_up.len) break;
            gave_up[count] = at;
            count += 1;
        }

        if (self.plan_arena == null) self.plan_arena = .init(self.gpa);
        self.plan.apply(self.plan_arena.?.allocator(), update) catch {};

        self.open(.dim);
        defer self.close(.dim);

        for (gave_up[0..count]) |at| {
            self.write("\nchock: plan step ");
            self.write(update.steps[at].id);
            self.write(" was given up");
            const said = self.subjectOf(update.steps[at]);
            if (said.len != 0) {
                self.write(": ");
                self.write(said);
            }
            self.write("\n");
        }

        const counts = self.plan.counts();
        var buffer: [32]u8 = undefined;
        self.write("\nchock: plan: ");
        self.write(std.fmt.bufPrint(&buffer, "{d}", .{counts.done}) catch "?");
        self.write(" of ");
        self.write(std.fmt.bufPrint(&buffer, "{d}", .{counts.total()}) catch "?");
        self.write(" done");
        if (counts.abandoned != 0) {
            self.write(", ");
            self.write(std.fmt.bufPrint(&buffer, "{d}", .{counts.abandoned}) catch "?");
            self.write(" given up");
        }
        if (self.stepInProgress()) |one| {
            self.write(", now on \"");
            self.write(one.subject);
            self.write("\"");
        }
        self.write("\n");
    }

    const max_said_steps = 64;

    fn subjectOf(self: *const Printer, step: chock_proto.event.PlanStep) []const u8 {
        if (step.subject.len != 0) return step.subject;
        const held = self.plan.find(step.id) orelse return "";
        return held.subject;
    }

    fn stepInProgress(self: *const Printer) ?chock_proto.state.Plan.Step {
        for (self.plan.steps.items) |step| {
            if (ui.isStatus(step.status, .in_progress)) return step;
        }
        return null;
    }

    fn open(self: *Printer, rank: tty.Rank) void {
        self.write(self.paint.open(rank));
    }

    fn close(self: *Printer, rank: tty.Rank) void {
        self.write(self.paint.close(rank));
    }

    /// A failed write is dropped on purpose. Through `src/tty.zig`'s standard
    /// output writer and never straight to the descriptor, because that writer is
    /// holding bytes that have not left yet.
    fn write(self: *Printer, bytes: []const u8) void {
        switch (self.out) {
            .stdout => if (!tty.writeOut(bytes)) {
                std.Io.File.stdout().writeStreamingAll(self.io, bytes) catch {};
            },
            .buffer => |buffer| buffer.bytes.appendSlice(buffer.gpa, bytes) catch {},
        }
    }

    fn flush(self: *Printer) void {
        switch (self.out) {
            .stdout => tty.flushOut(),
            .buffer => {},
        }
    }
};

fn appendUserMessage(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    text: []const u8,
) !void {
    var locked = try storage.lock(io);
    defer locked.unlock(io) catch {};
    const content = [_]chock_proto.event.ContentPart{.{ .text = text }};
    _ = try locked.append(
        gpa,
        io,
        .{ .message = .{ .role = .user, .content = &content } },
        std.Io.Timestamp.now(io, .real).toMilliseconds(),
    );
}

fn readMessage(arena: std.mem.Allocator, io: std.Io, options: Options) StartError![]const u8 {
    if (options.message_words.len != 0) {
        return std.mem.join(arena, " ", options.message_words);
    }

    var buffer: [4096]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &buffer);
    const text = reader.interface.allocRemaining(arena, .limited(max_stdin_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => {
            tty.print(
                .err,
                "chock run: the message on standard input is larger than {d} bytes.\n",
                .{max_stdin_bytes},
            );
            return error.Reported;
        },
        error.ReadFailed => {
            tty.print(.err, "chock run: standard input could not be read.\n", .{});
            return error.Reported;
        },
    };
    return std.mem.trim(u8, text, " \t\r\n");
}

fn resolveProject(arena: std.mem.Allocator, io: std.Io, options: Options) StartError![]const u8 {
    if (options.project) |given| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        var dir = std.Io.Dir.cwd().openDir(io, given, .{}) catch |err| {
            tty.print(.err, "chock run: {s} could not be opened: {s}\n", .{ given, @errorName(err) });
            return error.Reported;
        };
        defer dir.close(io);
        const length = dir.realPath(io, &buffer) catch |err| {
            tty.print(.err, "chock run: {s} has no real path: {s}\n", .{ given, @errorName(err) });
            return error.Reported;
        };
        return arena.dupe(u8, buffer[0..length]);
    }
    return std.process.currentPathAlloc(io, arena) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            tty.print(.err, "chock run: the current directory could not be read: {s}\n", .{@errorName(err)});
            return error.Reported;
        },
    };
}

fn chooseSessionId(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *std.process.Environ.Map,
    project_root: []const u8,
    options: Options,
) StartError![session_paths.id_length]u8 {
    if (options.session) |given| {
        if (!session_paths.isValidId(given)) {
            tty.print(.err, "chock run: \"{s}\" is not a session identifier.\n", .{given});
            return error.Reported;
        }
        return given[0..session_paths.id_length].*;
    }
    if (options.continue_newest) {
        const newest = session_paths.newestId(arena, io, env, project_root) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                tty.print(.err, "chock run: the newest session could not be found: {s}\n", .{@errorName(err)});
                return error.Reported;
            },
        };
        return newest orelse {
            tty.print(.err, "chock run: this project has no session to continue.\n", .{});
            return error.Reported;
        };
    }
    return session_paths.newId(io);
}

fn refuseAdoptWithNothingToAdopt(
    gpa: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    id: []const u8,
) StartError!void {
    switch (sessions_cmd.readinessOf(gpa, io, log_path, id)) {
        .ready => return,
        .no_such_session => tty.print(
            .err,
            "chock run: this project has no session {s} to adopt. `chock sessions` lists the " ++
                "sessions it does have.\n",
            .{id},
        ),
        .nothing_to_carry_on => tty.print(
            .err,
            "chock run: session {s} holds nothing to carry on from, so there is no conversation " ++
                "to adopt. Start it with a message instead.\n",
            .{id},
        ),
        .running => tty.print(
            .err,
            "chock run: session {s} is running now. The process that holds its log's lock owns " ++
                "it, and ownership is not taken from a session that is still using it.\n",
            .{id},
        ),
        // Fails closed: an absent answer is never a permissive answer.
        .unknown => tty.print(
            .err,
            "chock run: session {s} could not be read, or its lock could not be tested, so it " ++
                "was not adopted.\n",
            .{id},
        ),
    }
    return error.Reported;
}

const busy_detail = "another process took the session's log lock first, so it owns that session " ++
    "now. Nothing was lost: the log is whole, and `chock sessions` says who is running.";

fn projectKind(io: std.Io, project_root: []const u8) chock_core.prompt.Project {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const build_zig = std.fmt.bufPrint(&buffer, "{s}/build.zig", .{project_root}) catch return .{};
    _ = std.Io.Dir.cwd().statFile(io, build_zig, .{}) catch return .{};
    return .{ .kind = "Zig", .build_command = "zig build test" };
}

const ParseError = error{ HelpWanted, BadArguments } || std.mem.Allocator.Error;

const value_options = [_][]const u8{
    "--provider",
    "--model",
    "--project",
    "--session",
    "--agent-kind",
    "--org-bundle",
    "--instructions",
    "--dev-shell",
    "--policy-rule",
    "--max-turns",
    "--export-dir",
    "--export-syslog",
    subagent.flag.parent_session,
    subagent.flag.parent_kind,
    subagent.flag.spawn_reason,
    subagent.flag.scratchpad,
    subagent.flag.max_cost,
    subagent.flag.currency,
};

fn takesValue(argument: []const u8) bool {
    for (value_options) |name| {
        if (std.mem.eql(u8, argument, name)) return true;
    }
    return false;
}

fn parseOptions(arena: std.mem.Allocator, args: []const []const u8) ParseError!Options {
    var options = Options{};
    var words: std.ArrayList([]const u8) = .empty;
    var given: std.ArrayList([]const u8) = .empty;
    var rules: std.ArrayList(chock_policy.table.Rule) = .empty;
    var chain: std.ArrayList(chock_proto.event.SpawnLink) = .empty;

    var index: usize = 0;
    var only_words = false;
    while (index < args.len) : (index += 1) {
        const argument = args[index];

        if (only_words or argument.len == 0 or argument[0] != '-') {
            try words.append(arena, argument);
            continue;
        }
        if (std.mem.eql(u8, argument, "--")) {
            only_words = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--continue")) {
            options.continue_newest = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--adopt")) {
            options.adopt = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--allow-dirty")) {
            options.allow_dirty = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--no-notices")) {
            options.no_notices = true;
            continue;
        }

        if (!takesValue(argument)) {
            tty.print(.err, "chock run: there is no option named {s}.\n\n", .{argument});
            tty.print(.err, "{s}", .{usage_text});
            return error.BadArguments;
        }
        const value = value: {
            index += 1;
            if (index >= args.len) {
                tty.print(.err, "chock run: {s} needs a value.\n\n", .{argument});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            break :value args[index];
        };

        if (std.mem.eql(u8, argument, "--instructions")) {
            try given.append(arena, value);
        } else if (std.mem.eql(u8, argument, "--dev-shell")) {
            options.dev_shell = value;
        } else if (std.mem.eql(u8, argument, "--policy-rule")) {
            const rule = chock_policy.table.parseGivenRule(value) catch |err| {
                tty.print(
                    .err,
                    "chock run: --policy-rule \"{s}\" {s}.\n",
                    .{ value, chock_policy.table.givenRuleReason(err) },
                );
                return error.BadArguments;
            };
            try rules.append(arena, rule);
        } else if (std.mem.eql(u8, argument, "--provider")) {
            options.provider = value;
        } else if (std.mem.eql(u8, argument, "--model")) {
            options.model = value;
        } else if (std.mem.eql(u8, argument, "--project")) {
            options.project = value;
        } else if (std.mem.eql(u8, argument, "--session")) {
            options.session = value;
        } else if (std.mem.eql(u8, argument, "--agent-kind")) {
            options.agent_kind = value;
        } else if (std.mem.eql(u8, argument, "--org-bundle")) {
            options.org_bundle = value;
        } else if (std.mem.eql(u8, argument, "--export-dir")) {
            options.export_dir = value;
        } else if (std.mem.eql(u8, argument, "--export-syslog")) {
            options.export_syslog = value;
        } else if (std.mem.eql(u8, argument, subagent.flag.parent_session)) {
            options.parent_session = value;
        } else if (std.mem.eql(u8, argument, subagent.flag.parent_kind)) {
            try chain.append(arena, .{ .agent_kind = value, .reason = "" });
        } else if (std.mem.eql(u8, argument, subagent.flag.spawn_reason)) {
            if (chain.items.len == 0) {
                tty.print(
                    .err,
                    "chock run: {s} names why one agent started another, so it comes after " ++
                        "the {s} it belongs to.\n",
                    .{ subagent.flag.spawn_reason, subagent.flag.parent_kind },
                );
                return error.BadArguments;
            }
            chain.items[chain.items.len - 1].reason = value;
        } else if (std.mem.eql(u8, argument, subagent.flag.scratchpad)) {
            options.scratchpad = value;
        } else if (std.mem.eql(u8, argument, subagent.flag.max_cost)) {
            options.max_cost = std.fmt.parseFloat(f64, value) catch {
                tty.print(.err, "chock run: --max-cost takes a number, and \"{s}\" is not one.\n", .{value});
                return error.BadArguments;
            };
            if (!(options.max_cost.? > 0)) {
                tty.print(.err, "chock run: --max-cost has to be more than zero.\n", .{});
                return error.BadArguments;
            }
        } else if (std.mem.eql(u8, argument, subagent.flag.currency)) {
            options.currency = value;
        } else if (std.mem.eql(u8, argument, "--max-turns")) {
            options.max_turns = std.fmt.parseInt(usize, value, 10) catch {
                tty.print(.err, "chock run: --max-turns takes a number, and \"{s}\" is not one.\n", .{value});
                return error.BadArguments;
            };
            if (options.max_turns == 0) {
                tty.print(.err, "chock run: --max-turns 0 would run no turn at all.\n", .{});
                return error.BadArguments;
            }
        } else {
            tty.print(.err, "chock run: {s} is not handled yet.\n", .{argument});
            return error.BadArguments;
        }
    }

    if (options.session != null and options.continue_newest) {
        tty.print(.err, "chock run: --session and --continue name two different sessions.\n", .{});
        return error.BadArguments;
    }

    if (options.adopt) {
        if (options.session == null and !options.continue_newest) {
            tty.print(
                .err,
                "chock run: --adopt takes over a session that already exists, so it needs " ++
                    "--session <id> or --continue.\n",
                .{},
            );
            return error.BadArguments;
        }
        if (words.items.len != 0) {
            tty.print(
                .err,
                "chock run: --adopt carries on from what the session log already holds, so it " ++
                    "takes no message. Leave the message out, or run without --adopt to add one.\n",
                .{},
            );
            return error.BadArguments;
        }
    }

    options.message_words = words.items;
    options.instructions = given.items;
    options.policy_rules = rules.items;
    options.parent_chain = chain.items;
    return options;
}

const testing = std.testing;

test "--adopt takes over a session that exists, and refuses every shape that is not that" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const id = "01JQ" ++ "A" ** 22;
    try testing.expect(!(try parseOptions(arena, &.{"a message"})).adopt);
    try testing.expect((try parseOptions(arena, &.{ "--adopt", "--session", id })).adopt);
    try testing.expect((try parseOptions(arena, &.{ "--adopt", "--continue" })).adopt);
    try testing.expectEqual(
        @as(usize, 0),
        (try parseOptions(arena, &.{ "--adopt", "--session", id })).message_words.len,
    );

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--adopt"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--session") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "--continue") != null);

    said.clear();
    try testing.expectError(
        error.BadArguments,
        parseOptions(arena, &.{ "--adopt", "--session", id, "and", "also", "this" }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "takes no message") != null);
    try testing.expectEqualStrings("", said.out());
}

fn writeHandoverLog(
    gpa: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    id: []const u8,
    attempt: []const u8,
    base_commit: []const u8,
    reason: ?chock_proto.event.SessionEndReason,
) !void {
    const log = try chock_proto.log.Log.open(io, log_path, id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};
    _ = try locked.append(gpa, io, .{ .session_start = .{
        .agent_kind = "main",
        .model_alias = "local",
        .parent_session = "",
    } }, 1);
    _ = try locked.append(gpa, io, .{ .workspace_open = .{
        .kind = .worktree,
        .attempt = attempt,
        .path = "/state/somewhere",
        .base_commit = base_commit,
    } }, 2);
    if (reason) |ended| {
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = ended, .detail = "" } }, 3);
    }
}

test "the next owner finds the handed over workspace in the log, and takes nothing else" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const dir = buffer[0..len];

    const id = "01JQ" ++ "A" ** 22;
    const attempt = "01JQ" ++ "B" ** 22;
    const base_commit = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";

    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
    const work = try std.fmt.allocPrint(arena, "{s}/{s}.work", .{ dir, id });
    try std.Io.Dir.createDirAbsolute(io, work, .default_dir);

    try writeHandoverLog(gpa, io, log_path, id, attempt, base_commit, .handed_over);

    try testing.expect(takenOver(gpa, io, arena, log_path, work) == null);

    const checkout = try std.fmt.allocPrint(arena, "{s}/{s}", .{ work, attempt });
    try std.Io.Dir.createDirAbsolute(io, checkout, .default_dir);

    const taken = takenOver(gpa, io, arena, log_path, work).?;
    try testing.expectEqualStrings(attempt, &taken.attempt);
    try testing.expectEqualStrings(base_commit, taken.base_commit);
}

test "a workspace opened after the handover belongs to the owner that came next" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const dir = buffer[0..len];

    const id = "01JQ" ++ "A" ** 22;
    const first_attempt = "01JQ" ++ "B" ** 22;
    const second_attempt = "01JQ" ++ "C" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
    const work = try std.fmt.allocPrint(arena, "{s}/{s}.work", .{ dir, id });
    try std.Io.Dir.createDirAbsolute(io, work, .default_dir);
    for ([_][]const u8{ first_attempt, second_attempt }) |one| {
        const checkout = try std.fmt.allocPrint(arena, "{s}/{s}", .{ work, one });
        try std.Io.Dir.createDirAbsolute(io, checkout, .default_dir);
    }

    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};
        _ = try locked.append(gpa, io, .{ .workspace_open = .{
            .kind = .worktree,
            .attempt = first_attempt,
            .path = "/state/a",
            .base_commit = "aaaa",
        } }, 1);
        _ = try locked.append(gpa, io, .{ .session_end = .{
            .reason = .handed_over,
            .detail = "",
        } }, 2);
    }

    const taken = takenOver(gpa, io, arena, log_path, work).?;
    try testing.expectEqualStrings(first_attempt, &taken.attempt);

    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};
        _ = try locked.append(gpa, io, .{ .workspace_open = .{
            .kind = .worktree,
            .attempt = second_attempt,
            .path = "/state/b",
            .base_commit = "bbbb",
        } }, 3);
    }

    try testing.expect(takenOver(gpa, io, arena, log_path, work) == null);
}

test "only a session that handed over gives its workspace away" {
    const gpa = testing.allocator;
    const io = testing.io;

    const others = [_]?chock_proto.event.SessionEndReason{
        null,
        .finished,
        .errored,
        .canceled_by_user,
        .budget_reached,
    };
    var answered: std.ArrayList(u8) = .empty;
    defer answered.deinit(gpa);
    var wanted: std.ArrayList(u8) = .empty;
    defer wanted.deinit(gpa);

    for (others) |reason| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(io, &buffer);
        const dir = buffer[0..len];

        const id = "01JQ" ++ "A" ** 22;
        const attempt = "01JQ" ++ "B" ** 22;
        const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
        const work = try std.fmt.allocPrint(arena, "{s}/{s}.work", .{ dir, id });
        const checkout = try std.fmt.allocPrint(arena, "{s}/{s}", .{ work, attempt });
        try std.Io.Dir.createDirAbsolute(io, work, .default_dir);
        try std.Io.Dir.createDirAbsolute(io, checkout, .default_dir);

        try writeHandoverLog(gpa, io, log_path, id, attempt, "a1b2c3", reason);
        const named: []const u8 = if (reason) |one| @tagName(one) else "no ending at all";
        try answered.print(gpa, "{s}: {s}\n", .{
            named,
            if (takenOver(gpa, io, arena, log_path, work) == null) "nothing adopted" else "adopted",
        });
        try wanted.print(gpa, "{s}: nothing adopted\n", .{named});
    }

    try testing.expectEqualStrings(wanted.items, answered.items);
}

test "a run that adopted a workspace never removes it, however it fails" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const tmp_path = buffer[0..len];

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const project = try std.fmt.allocPrint(arena, "{s}/project", .{tmp_path});
    const scratch = try std.fmt.allocPrint(arena, "{s}/scratch", .{tmp_path});
    try std.Io.Dir.createDirAbsolute(io, project, .default_dir);
    try std.Io.Dir.createDirAbsolute(io, scratch, .default_dir);

    var env = try std.testing.environ.createMap(arena);
    try env.put("GIT_CEILING_DIRECTORIES", tmp_path);
    try makeGitProject(arena, io, &env, project);

    const attempt = "01JQ" ++ "B" ** 22;
    var first = try chock_workspace.Workspace.open(arena, io, &env, project, scratch, attempt, null);
    const base_commit = try arena.dupe(u8, first.kind.worktree.base_commit);
    const written = try std.fmt.allocPrint(arena, "{s}/agent-wrote-this.txt", .{first.workPath()});
    {
        var handle = try std.Io.Dir.createFileAbsolute(io, written, .{});
        defer handle.close(io);
        try handle.writeStreamingAll(io, "work nobody committed\n");
    }
    first.keep(arena);

    var second = try chock_workspace.Workspace.adopt(
        arena,
        io,
        &env,
        project,
        scratch,
        attempt,
        base_commit,
        null,
    );
    switch (releaseOnFailure(true)) {
        .keep => second.keep(arena),
        .remove => second.close(arena, io, &env, null) catch {},
        .hand_on => unreachable,
    }
    try testing.expectEqual(Cleanup.remove, releaseOnFailure(false));

    const stat = try std.Io.Dir.cwd().statFile(io, written, .{});
    try testing.expectEqual(@as(u64, "work nobody committed\n".len), stat.size);

    var third = try chock_workspace.Workspace.adopt(
        arena,
        io,
        &env,
        project,
        scratch,
        attempt,
        base_commit,
        null,
    );
    try testing.expectEqualStrings(base_commit, third.kind.worktree.base_commit);
    third.keep(arena);
}

test "a handover keeps the workspace and the scratchpad, and applies nothing" {
    try testing.expect(handedOver(Exit.handed_over));
    try testing.expect(!handedOver(Exit.finished));
    try testing.expect(!handedOver(Exit.faulted));
    try testing.expect(!handedOver(Exit.refused));
    try testing.expect(!handedOver(error.Busy));

    try testing.expectEqual(Cleanup.hand_on, cleanupFor(.handed_over, .nothing_to_apply));
    try testing.expectEqual(Cleanup.keep, cleanupFor(.faulted, .nothing_to_apply));
    try testing.expectEqual(Cleanup.remove, cleanupFor(.finished, .nothing_to_apply));

    const nothing_shipped = ShippingReport{};
    try testing.expectEqual(
        Exit.handed_over,
        exitWithApply(.handed_over, .nothing_to_apply, &nothing_shipped),
    );
}

test "the words that are not options become the message, in the order they were given" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const options = try parseOptions(arena, &.{ "--model", "a-model", "add", "a", "test" });
    try testing.expectEqualStrings("a-model", options.model.?);
    try testing.expectEqual(@as(usize, 3), options.message_words.len);
    const joined = try std.mem.join(arena, " ", options.message_words);
    try testing.expectEqualStrings("add a test", joined);
}

test "no message on the command line leaves the words empty, which is what makes a pipe work" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const options = try parseOptions(arena, &.{ "--provider", "local" });
    try testing.expectEqual(@as(usize, 0), options.message_words.len);
    try testing.expectEqualStrings("local", options.provider.?);
}

test "a message that starts with a dash is a message after --, and an option otherwise" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const options = try parseOptions(arena, &.{ "--", "--not-an-option", "really" });
    try testing.expectEqual(@as(usize, 2), options.message_words.len);
    try testing.expectEqualStrings("--not-an-option", options.message_words[0]);

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--not-an-option"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--not-an-option") != null);
    try testing.expectEqualStrings("", said.out());
}

test "an unparsable command line fails, and never runs a session with a guessed value" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const refusals = [_]struct { argv: []const []const u8, names: []const u8 }{
        .{ .argv = &.{"--model"}, .names = "--model" },
        .{ .argv = &.{ "--max-turns", "lots" }, .names = "lots" },
        .{ .argv = &.{ "--max-turns", "0" }, .names = "--max-turns 0" },
        .{ .argv = &.{"--nonsense"}, .names = "--nonsense" },
        .{
            .argv = &.{ "--continue", "--session", "01JQ" ++ "A" ** 22 },
            .names = "two different sessions",
        },
    };
    for (refusals) |one| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(arena, one.argv));
        try testing.expect(std.mem.indexOf(u8, said.err(), one.names) != null);
        try testing.expectEqualStrings("", said.out());
    }
}

test "--help is asked for on purpose, so it is not a usage failure" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    try testing.expectError(error.HelpWanted, parseOptions(arena_state.allocator(), &.{"--help"}));
}

test "the exit code comes from the last session end in the log, and a log with none is a fault" {
    const gpa = testing.allocator;
    const io = testing.io;

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01RUN");
        const storage = backing.storage();
        defer storage.close(io);
        var locked = try storage.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "hello" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        try locked.unlock(io);
        try testing.expectEqual(Exit.faulted, try finalExit(gpa, io, storage));
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01RUN");
        const storage = backing.storage();
        defer storage.close(io);
        var locked = try storage.lock(io);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 1);
        try locked.unlock(io);
        try testing.expectEqual(Exit.finished, try finalExit(gpa, io, storage));
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01RUN");
        const storage = backing.storage();
        defer storage.close(io);
        var locked = try storage.lock(io);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 1);
        _ = try locked.append(gpa, io, .{ .session_end = .{
            .reason = .canceled_by_user,
            .detail = "nobody answered",
        } }, 2);
        try locked.unlock(io);
        try testing.expectEqual(Exit.refused, try finalExit(gpa, io, storage));
    }
}

test "an option that does not exist is named as such, and never as one that needs a value" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--nonsense"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "no option named --nonsense") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "needs a value") == null);

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "--nonsense", "add" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "no option named --nonsense") != null);
    said.clear();

    var refused: std.ArrayList(u8) = .empty;
    defer refused.deinit(gpa);

    for (value_options) |name| {
        try testing.expect(takesValue(name));
        const before: []const []const u8 = if (std.mem.eql(u8, name, subagent.flag.spawn_reason))
            &.{ subagent.flag.parent_kind, "main" }
        else
            &.{};
        const argv = try std.mem.concat(arena, []const u8, &.{ before, &.{ name, valueFor(name) } });
        _ = parseOptions(arena, argv) catch |err| {
            try refused.print(gpa, "{s} was refused with its own value: {t}\n", .{ name, err });
        };
    }

    try testing.expectEqualStrings("", refused.items);
}

test "the flags a parent writes are the flags this parser reads" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const prepared = chock_core.subagent.Prepared{
        .child_session = try arena.dupe(u8, "01JQ" ++ "A" ** 22),
        .log_path = try arena.dupe(u8, "/tmp/chock/child.jsonl"),
        .scratchpad_path = try arena.dupe(u8, "/tmp/chock/01PARENT/agents/01CHILD"),
    };
    const above = [_]chock_proto.event.SpawnLink{
        .{ .agent_kind = "main", .reason = "split the work" },
        .{ .agent_kind = "coder", .reason = "review the parser" },
    };
    const argv = try chock_core.subagent.commandLine(arena, .{
        .exe_path = "/nix/store/aaa/bin/chock",
        .project_root = "/home/ross/project",
        .parent_session = "01JQ" ++ "B" ** 22,
        .parent_chain = &above,
        .provider = "local",
        .model = "a-model",
    }, .{
        .agent_kind = "reviewer",
        .task = "read the parser",
        .reason = "review the parser",
        .budget = .{ .max_cost = 1.25, .currency = "USD" },
    }, prepared);

    const options = try parseOptions(arena, argv[2..]);

    try testing.expectEqualStrings("reviewer", options.agent_kind);
    try testing.expectEqualStrings("01JQ" ++ "B" ** 22, options.parent_session);
    try testing.expectEqualStrings("/tmp/chock/01PARENT/agents/01CHILD", options.scratchpad);
    try testing.expectEqual(@as(f64, 1.25), options.max_cost.?);
    try testing.expectEqualStrings("USD", options.currency);
    try testing.expectEqualStrings("/home/ross/project", options.project.?);
    try testing.expectEqualStrings("local", options.provider.?);
    try testing.expectEqualStrings("a-model", options.model.?);
    try testing.expectEqual(@as(usize, 1), options.message_words.len);
    try testing.expectEqualStrings("read the parser", options.message_words[0]);

    const chain = spawnChain(options);
    try testing.expectEqual(@as(usize, 2), chain.len);
    try testing.expectEqualStrings("main", chain[0].agent_kind);
    try testing.expectEqualStrings("split the work", chain[0].reason);
    try testing.expectEqualStrings("coder", chain[1].agent_kind);
    try testing.expectEqualStrings("review the parser", chain[1].reason);
    try testing.expectEqual(@as(usize, 3), chain.len + 1);
    try testing.expectEqual(@as(usize, 0), spawnChain(.{}).len);

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    try testing.expectError(
        error.BadArguments,
        parseOptions(arena, &.{ subagent.flag.spawn_reason, "review the parser" }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), subagent.flag.spawn_reason) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), subagent.flag.parent_kind) != null);
    try testing.expectEqualStrings("", said.out());
}

test "a budget ceiling is said out loud, whether or not the bundle names a subject" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const anonymous = try chock_policy.org.parse(arena, ".{ .budget = .{ .max_cost = 5.0 } }", null);
    reportOrgBundle(anonymous, 0);
    try testing.expect(std.mem.indexOf(u8, said.err(), "budget ceiling 5 USD") != null);

    said.clear();
    const no_ceiling = try chock_policy.org.parse(arena, ".{ .rules = .{} }", null);
    reportOrgBundle(no_ceiling, 0);
    try testing.expect(std.mem.indexOf(u8, said.err(), "budget ceiling") == null);
}

test "an org budget ceiling binds this session, and a project above it is refused out loud" {
    const gpa = testing.allocator;

    const capped: chock_policy.org.Bundle = .{ .budget = .{ .max_cost = 5.0, .currency = "USD" } };

    const modest = chock_cost.budget.Budget{ .max_cost = 2.5, .currency = "USD" };
    const kept = (try budgetUnderOrg(gpa, modest, .{}, &capped)).?;
    try testing.expectEqual(@as(f64, 2.5), kept.max_cost);
    try testing.expectEqualStrings("USD", kept.currency);

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const greedy = chock_cost.budget.Budget{ .max_cost = 50.0, .currency = "USD" };
    try testing.expectError(error.Reported, budgetUnderOrg(gpa, greedy, .{}, &capped));
    try testing.expect(std.mem.indexOf(u8, said.err(), "50 USD") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "5 USD") != null);
    try testing.expectEqualStrings("", said.out());
}

test "an org bundle with no ceiling leaves a project alone, and one with a ceiling caps a project that wrote none" {
    const gpa = testing.allocator;

    const rules_only: chock_policy.org.Bundle = .{};
    const own = chock_cost.budget.Budget{ .max_cost = 50.0, .currency = "USD" };
    const untouched = (try budgetUnderOrg(gpa, own, .{}, &rules_only)).?;
    try testing.expectEqual(@as(f64, 50.0), untouched.max_cost);

    const no_bundle = (try budgetUnderOrg(gpa, own, .{}, null)).?;
    try testing.expectEqual(@as(f64, 50.0), no_bundle.max_cost);

    const capped: chock_policy.org.Bundle = .{ .budget = .{ .max_cost = 5.0, .currency = "USD" } };
    const from_org = (try budgetUnderOrg(gpa, null, .{}, &capped)).?;
    try testing.expectEqual(@as(f64, 5.0), from_org.max_cost);
    try testing.expectEqualStrings("USD", from_org.currency);

    try testing.expectEqual(
        @as(?chock_cost.budget.Budget, null),
        try budgetUnderOrg(gpa, null, .{}, &rules_only),
    );
}

test "the org ceiling is folded after the parent slice, so no source of a budget goes around it" {
    const gpa = testing.allocator;
    const capped: chock_policy.org.Bundle = .{ .budget = .{ .max_cost = 5.0, .currency = "USD" } };

    const sliced = (try budgetUnderOrg(gpa, .{ .max_cost = 5.0, .currency = "USD" }, .{
        .max_cost = 1.25,
    }, &capped)).?;
    try testing.expectEqual(@as(f64, 1.25), sliced.max_cost);

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    try testing.expectError(error.Reported, budgetUnderOrg(gpa, null, .{
        .max_cost = 900.0,
        .currency = "JPY",
    }, &capped));
    try testing.expect(std.mem.indexOf(u8, said.err(), "JPY") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "USD") != null);
}

test "a ceiling that names no currency is USD, the same default a project gets" {
    const plain: chock_policy.org.Bundle = .{ .budget = .{ .max_cost = 5.0 } };
    const ceiling = orgBudgetCeiling(&plain).?;
    try testing.expectEqual(@as(f64, 5.0), ceiling.max_cost);
    try testing.expectEqualStrings(chock_cost.budget.default_currency, ceiling.currency);

    const yen: chock_policy.org.Bundle = .{ .budget = .{ .max_cost = 900.0, .currency = "JPY" } };
    try testing.expectEqualStrings("JPY", orgBudgetCeiling(&yen).?.currency);

    try testing.expectEqual(@as(?chock_cost.budget.Budget, null), orgBudgetCeiling(null));
    const rules_only: chock_policy.org.Bundle = .{};
    try testing.expectEqual(@as(?chock_cost.budget.Budget, null), orgBudgetCeiling(&rules_only));
}

test "a budget slice narrows what chock.zon allows and can never widen it" {
    const gpa = testing.allocator;
    const file_cap = chock_cost.budget.Budget{ .max_cost = 5.0, .currency = "USD" };

    try testing.expectEqual(@as(f64, 5.0), (try budgetUnderOrg(gpa, file_cap, .{}, null)).?.max_cost);

    try testing.expectEqual(
        @as(f64, 1.25),
        (try budgetUnderOrg(gpa, file_cap, .{ .max_cost = 1.25 }, null)).?.max_cost,
    );

    try testing.expectEqual(
        @as(f64, 5.0),
        (try budgetUnderOrg(gpa, file_cap, .{ .max_cost = 500.0 }, null)).?.max_cost,
    );

    const sliced = (try budgetUnderOrg(gpa, null, .{ .max_cost = 1.25 }, null)).?;
    try testing.expectEqual(@as(f64, 1.25), sliced.max_cost);
    try testing.expectEqualStrings("USD", sliced.currency);

    const in_yen = (try budgetUnderOrg(gpa, file_cap, .{
        .max_cost = 900.0,
        .currency = "JPY",
    }, null)).?;
    try testing.expectEqual(@as(f64, 900.0), in_yen.max_cost);
    try testing.expectEqualStrings("JPY", in_yen.currency);

    try testing.expectEqual(
        @as(?chock_cost.budget.Budget, null),
        try budgetUnderOrg(gpa, null, .{}, null),
    );
}

fn valueFor(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "--max-turns")) return "3";
    if (std.mem.eql(u8, name, subagent.flag.max_cost)) return "1.25";
    if (std.mem.eql(u8, name, "--session")) return "01JQ" ++ "A" ** 22;
    if (std.mem.eql(u8, name, "--policy-rule")) return "git.push=allow";
    return "a-value";
}

test "the dirty tree warning names the count, the split, and the flag" {
    const gpa = testing.allocator;
    const text = try dirtyWarning(gpa, .{ .modified = 9, .untracked = 3 });
    defer gpa.free(text);
    try testing.expectEqualStrings(
        "chock run: 12 uncommitted files will not be visible to the agent\n" ++
            "           (9 modified, 3 untracked). Pass --allow-dirty to include them.\n",
        text,
    );
    const parsed = try parseOptions(gpa, &.{"--allow-dirty"});
    try testing.expect(parsed.allow_dirty);
    try testing.expect(std.mem.indexOf(u8, text, "--allow-dirty") != null);
}

test "--dev-shell takes a value, and a run that names none leaves the file to decide" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const named = try parseOptions(arena, &.{ "--dev-shell", "ci", "do the thing" });
    try testing.expectEqualStrings("ci", named.dev_shell.?);

    const quiet = try parseOptions(arena, &.{"do the thing"});
    try testing.expectEqual(@as(?[]const u8, null), quiet.dev_shell);
}

test "--policy-rule is repeatable, and a shape that is not <action>=<decision> is refused" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = try parseOptions(arena, &.{
        "--policy-rule", "net.fetch.*=allow",
        "--policy-rule", "git.push=deny",
        "do the thing",
    });
    try testing.expectEqual(@as(usize, 2), parsed.policy_rules.len);
    try testing.expectEqualStrings("net.fetch.*", parsed.policy_rules[0].action.?);
    try testing.expectEqual(chock_policy.table.Decision.allow, parsed.policy_rules[0].decision);
    try testing.expectEqualStrings("git.push", parsed.policy_rules[1].action.?);
    try testing.expectEqual(chock_policy.table.Decision.deny, parsed.policy_rules[1].decision);

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    try testing.expectError(
        error.BadArguments,
        parseOptions(arena, &.{ "--policy-rule", "git.push" }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "holds no =") != null);
}

test "a clean tree gets no warning at all, so the message stays worth reading" {
    const clean = chock_workspace.worktree.Uncommitted{};
    try testing.expect(!clean.any());
    try testing.expectEqual(@as(usize, 0), clean.total());

    const dirty = chock_workspace.worktree.Uncommitted{ .untracked = 1 };
    try testing.expect(dirty.any());
}

test "--allow-dirty is off unless it is asked for, and it takes no value" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const plain = try parseOptions(arena, &.{"fix the parser"});
    try testing.expect(!plain.allow_dirty);

    const with_flag = try parseOptions(arena, &.{ "--allow-dirty", "fix", "the", "parser" });
    try testing.expect(with_flag.allow_dirty);
    try testing.expectEqual(@as(usize, 3), with_flag.message_words.len);
    try testing.expect(!takesValue("--allow-dirty"));
}

test "the ref a session's work lands on is the session's own, never a branch of the user" {
    const gpa = testing.allocator;
    const ref = try applyRef(gpa, "01JQABCDEFGHJKMNPQRSTVWXYZ");
    defer gpa.free(ref);
    try testing.expectEqualStrings("refs/chock/01JQABCDEFGHJKMNPQRSTVWXYZ", ref);
    try testing.expect(std.mem.startsWith(u8, ref, "refs/chock/"));
    try testing.expect(!std.mem.startsWith(u8, ref, "refs/heads/"));
}

test "a session that finished but whose work was refused does not exit zero" {
    const quiet = ShippingReport{};
    try testing.expectEqual(Exit.refused, exitWithApply(.finished, .refused, &quiet));
    try testing.expectEqual(Exit.faulted, exitWithApply(.finished, .failed, &quiet));

    try testing.expectEqual(Exit.faulted, exitWithApply(.finished, .uncommitted, &quiet));

    try testing.expectEqual(Exit.finished, exitWithApply(.finished, .nothing_to_apply, &quiet));
    try testing.expectEqual(Exit.finished, exitWithApply(.finished, .landed, &quiet));

    for ([_]Exit{ .faulted, .budget, .no_progress, .turn_limit, .refused }) |session_exit| {
        for ([_]Applied{ .nothing_to_apply, .landed, .refused, .failed, .uncommitted }) |applied| {
            try testing.expectEqual(session_exit, exitWithApply(session_exit, applied, &quiet));
        }
    }

    var lost = ShippingReport{};
    lost.add(.{ .name = "/var/audit/chock/01JQ.jsonl", .required = true, .health = .{
        .delivered = 2,
        .faults = 1,
        .first_fault = error.ConnectionRefused,
        .stalled_at = 96,
    } });
    try testing.expectEqual(Exit.audit_gap, exitWithApply(.finished, .landed, &lost));
    try testing.expectEqual(Exit.audit_gap, exitWithApply(.finished, .nothing_to_apply, &lost));
    try testing.expectEqual(Exit.refused, exitWithApply(.finished, .refused, &lost));
    try testing.expectEqual(Exit.faulted, exitWithApply(.faulted, .landed, &lost));
}

test "only a clean ending removes the workspace, and every way a session can go wrong keeps it" {
    try testing.expectEqual(Cleanup.remove, cleanupFor(.finished, .landed));
    try testing.expectEqual(Cleanup.remove, cleanupFor(.finished, .nothing_to_apply));

    try testing.expectEqual(Cleanup.keep, cleanupFor(.finished, .uncommitted));
    try testing.expectEqual(Cleanup.keep, cleanupFor(.finished, .refused));
    try testing.expectEqual(Cleanup.keep, cleanupFor(.finished, .failed));

    for ([_]Exit{ .faulted, .budget, .no_progress, .turn_limit, .refused, .usage }) |ended| {
        for ([_]Applied{ .nothing_to_apply, .landed, .refused, .failed, .uncommitted }) |applied| {
            try testing.expectEqual(Cleanup.keep, cleanupFor(ended, applied));
        }
    }

    try testing.expectEqual(Cleanup.keep, cleanupFor(null, .landed));
}

test "the run keeps the workspace on an abnormal ending, with the agent's file still in it" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const tmp_path = buffer[0..len];

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const project = try std.fmt.allocPrint(arena, "{s}/project", .{tmp_path});
    const scratch = try std.fmt.allocPrint(arena, "{s}/scratch", .{tmp_path});
    try std.Io.Dir.createDirAbsolute(io, project, .default_dir);
    try std.Io.Dir.createDirAbsolute(io, scratch, .default_dir);

    var env = try std.testing.environ.createMap(arena);
    try env.put("GIT_CEILING_DIRECTORIES", tmp_path);
    try makeGitProject(arena, io, &env, project);

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    for ([_]Cleanup{ .keep, .remove, .hand_on }) |verdict| {
        said.clear();
        var workspace = try chock_workspace.Workspace.open(
            arena,
            io,
            &env,
            project,
            scratch,
            @tagName(verdict),
            null,
        );
        const written = try std.fmt.allocPrint(
            arena,
            "{s}/agent-wrote-this.txt",
            .{workspace.workPath()},
        );
        {
            var handle = try std.Io.Dir.createFileAbsolute(io, written, .{});
            defer handle.close(io);
            try handle.writeStreamingAll(io, "work nobody committed\n");
        }

        const work_path = try arena.dupe(u8, workspace.workPath());
        takeDownWorkspace(&workspace, verdict, arena, io, &env, scratch);

        switch (verdict) {
            .keep, .hand_on => {
                const stat = try std.Io.Dir.cwd().statFile(io, written, .{});
                try testing.expectEqual(@as(u64, "work nobody committed\n".len), stat.size);
                if (verdict == .keep) {
                    try testing.expect(std.mem.indexOf(u8, said.err(), work_path) != null);
                }
            },
            .remove => {
                try testing.expectError(
                    error.FileNotFound,
                    std.Io.Dir.cwd().statFile(io, written, .{}),
                );
                try testing.expectEqualStrings("", said.err());
            },
        }
        try testing.expectEqualStrings("", said.out());
    }
}

fn makeGitProject(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project: []const u8,
) !void {
    const steps: []const []const []const u8 = &.{
        &.{"init"},
        &.{ "config", "user.email", "test@example.com" },
        &.{ "config", "user.name", "Test" },
    };
    for (steps) |argv| {
        var output = try chock_workspace.git.run(arena, io, env, project, argv, null);
        defer output.deinit(arena);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    }

    const tracked = try std.fmt.allocPrint(arena, "{s}/tracked.txt", .{project});
    {
        var handle = try std.Io.Dir.createFileAbsolute(io, tracked, .{});
        defer handle.close(io);
        try handle.writeStreamingAll(io, "hello\n");
    }

    const commits: []const []const []const u8 = &.{
        &.{ "add", "tracked.txt" },
        &.{ "commit", "-m", "first commit" },
    };
    for (commits) |argv| {
        var output = try chock_workspace.git.run(arena, io, env, project, argv, null);
        defer output.deinit(arena);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    }
}

const CountingToolRunner = struct {
    calls: usize = 0,
    last_arguments: []const u8 = "",

    fn runner(self: *CountingToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatch };

    fn dispatch(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        _ = io;
        const self: *CountingToolRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.last_arguments = call.arguments;
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = try gpa.dupe(u8, "the real git ran"),
            .is_error = false,
            .truncated = false,
        };
    }
};

const CountingArbiter = struct {
    permitted: bool,
    asks: usize = 0,

    action: Kept(64) = .{},
    tool: Kept(64) = .{},
    detail: Kept(512) = .{},
    source: Kept(64) = .{},

    fn Kept(comptime size: usize) type {
        return struct {
            bytes: [size]u8 = undefined,
            len: usize = 0,

            fn set(self: *@This(), text: []const u8) void {
                self.len = @min(text.len, size);
                @memcpy(self.bytes[0..self.len], text[0..self.len]);
            }

            fn read(self: *const @This()) []const u8 {
                return self.bytes[0..self.len];
            }
        };
    }

    fn asker(self: *CountingArbiter, locked: *chock_core.arbiter.Locked) chock_core.arbiter.Asker {
        return .{ .arbiter = .{ .ptr = self, .vtable = &vtable }, .locked = locked };
    }

    const vtable = chock_core.arbiter.Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *chock_core.arbiter.Locked,
        ask: chock_core.arbiter.Ask,
    ) chock_core.arbiter.Answer {
        _ = gpa;
        _ = io;
        _ = locked;
        const self: *CountingArbiter = @ptrCast(@alignCast(ptr));
        self.asks += 1;
        self.action.set(ask.action);
        self.tool.set(ask.tool);
        self.detail.set(ask.detail);
        self.source.set(ask.source);
        return .{
            .permitted = self.permitted,
            .outcome = if (self.permitted) "allowed_by_policy" else "refused_by_user",
        };
    }
};

fn driveGitRunner(
    gpa: std.mem.Allocator,
    io: std.Io,
    arbitrator: *CountingArbiter,
    inner: *CountingToolRunner,
    arguments: []const u8,
) !chock_proto.event.ToolResult {
    var log = try PermittingLog.init(gpa);
    defer log.deinit(io);
    try log.arm(io);

    var shim = GitToolRunner{ .inner = inner.runner(), .asker = arbitrator.asker(&log.locked) };
    return shim.runner().dispatch(gpa, io, .{
        .call_id = "call1",
        .tool = "run_command",
        .arguments = arguments,
    });
}

test "a subcommand the shim classifies reaches a person, and is refused when nobody can answer" {
    const gpa = testing.allocator;
    const io = testing.io;

    for ([_][]const u8{
        "{\"argv\":[\"git\",\"push\",\"origin\",\"main\"]}",
        "{\"argv\":[\"git\",\"frobnicate\"]}",
        "{\"argv\":[\"git\",\"-c\",\"core.pager=sh -c id\",\"log\"]}",
    }) |arguments| {
        var inner = CountingToolRunner{};
        var shim = GitToolRunner{ .inner = inner.runner() };

        const result = try shim.runner().dispatch(gpa, io, .{
            .call_id = "call1",
            .tool = "run_command",
            .arguments = arguments,
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try testing.expectEqual(@as(usize, 0), inner.calls);
        try testing.expect(result.is_error);
        try testing.expect(std.mem.indexOf(
            u8,
            result.output,
            chock_core.arbiter.not_asked.outcome,
        ) != null);
    }
}

test "the question a git subcommand asks names the act, the tool that ran it, and the effect" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arbitrator = CountingArbiter{ .permitted = false };
    var inner = CountingToolRunner{};
    const result = try driveGitRunner(
        gpa,
        io,
        &arbitrator,
        &inner,
        "{\"argv\":[\"git\",\"push\",\"origin\",\"main\"]}",
    );
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try testing.expectEqual(@as(usize, 1), arbitrator.asks);
    try testing.expectEqualStrings("git.push", arbitrator.action.read());
    try testing.expectEqualStrings("run_command", arbitrator.tool.read());
    try testing.expectEqualStrings("git", arbitrator.source.read());
    try testing.expect(std.mem.indexOf(
        u8,
        arbitrator.detail.read(),
        "the subcommand runs inside the sandbox",
    ) != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "git.push") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "refused_by_user") != null);
    try testing.expectEqual(@as(usize, 0), inner.calls);
}

test "a subcommand that reaches another host is asked about, and an approved one still does not run" {
    const gpa = testing.allocator;
    const io = testing.io;

    for ([_][]const u8{
        "{\"argv\":[\"git\",\"fetch\",\"origin\"]}",
        "{\"argv\":[\"git\",\"pull\"]}",
        "{\"argv\":[\"git\",\"clone\",\"https://example.invalid/x.git\"]}",
        "{\"argv\":[\"git\",\"-C\",\"sub\",\"fetch\"]}",
    }) |arguments| {
        var arbitrator = CountingArbiter{ .permitted = true };
        var inner = CountingToolRunner{};
        const result = try driveGitRunner(gpa, io, &arbitrator, &inner, arguments);
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try testing.expectEqual(@as(usize, 1), arbitrator.asks);
        try testing.expectEqual(@as(usize, 0), inner.calls);
        try testing.expect(result.is_error);
        try testing.expect(std.mem.indexOf(u8, result.output, "not built yet") != null);
        try testing.expect(std.mem.indexOf(u8, result.output, "not a refusal") != null);
        try testing.expect(std.mem.indexOf(u8, result.output, "has no network") == null);
    }
}

test "an approved push with no way to hold a credential is refused loudly, never run" {
    const gpa = testing.allocator;
    const io = testing.io;

    var arbitrator = CountingArbiter{ .permitted = true };
    var inner = CountingToolRunner{};
    const result = try driveGitRunner(
        gpa,
        io,
        &arbitrator,
        &inner,
        "{\"argv\":[\"git\",\"push\",\"origin\",\"main\"]}",
    );
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try testing.expectEqual(@as(usize, 1), arbitrator.asks);
    try testing.expectEqual(@as(usize, 0), inner.calls);
    try testing.expect(result.is_error);
    try testing.expect(std.mem.indexOf(u8, result.output, "no way to hold a credential") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "not a refusal") != null);
}

test "a read only subcommand reaches the real git and asks nobody at all" {
    const gpa = testing.allocator;
    const io = testing.io;

    for ([_][]const u8{
        "{\"argv\":[\"git\",\"status\",\"--short\"]}",
        "{\"argv\":[\"git\",\"log\",\"--oneline\"]}",
        "{\"argv\":[\"git\",\"diff\"]}",
        "{\"argv\":[\"git\",\"--version\"]}",
        "{\"argv\":[\"zig\",\"build\",\"test\"]}",
        "{\"argv\":[]}",
        "not json at all",
    }) |arguments| {
        var arbitrator = CountingArbiter{ .permitted = false };
        var inner = CountingToolRunner{};
        const result = try driveGitRunner(gpa, io, &arbitrator, &inner, arguments);
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try testing.expectEqual(@as(usize, 0), arbitrator.asks);
        try testing.expectEqual(@as(usize, 1), inner.calls);
        try testing.expect(!result.is_error);
    }

    var arbitrator = CountingArbiter{ .permitted = false };
    var inner = CountingToolRunner{};
    var log = try PermittingLog.init(gpa);
    defer log.deinit(io);
    try log.arm(io);
    var shim = GitToolRunner{ .inner = inner.runner(), .asker = arbitrator.asker(&log.locked) };
    const result = try shim.runner().dispatch(gpa, io, .{
        .call_id = "call1",
        .tool = "write_file",
        .arguments = "{\"path\":\"x\",\"content\":\"{\\\"argv\\\":[\\\"git\\\",\\\"fetch\\\"]}\"}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);
    try testing.expectEqual(@as(usize, 0), arbitrator.asks);
    try testing.expectEqual(@as(usize, 1), inner.calls);
}

test "an approved workspace subcommand reaches the real git, git commit included" {
    const gpa = testing.allocator;
    const io = testing.io;

    for ([_][]const u8{
        "{\"argv\":[\"git\",\"add\",\"-A\"]}",
        "{\"argv\":[\"git\",\"commit\",\"-m\",\"the work\"]}",
        "{\"argv\":[\"git\",\"checkout\",\"-b\",\"topic\"]}",
        "{\"argv\":[\"git\",\"branch\",\"-D\",\"topic\"]}",
    }) |arguments| {
        var arbitrator = CountingArbiter{ .permitted = true };
        var inner = CountingToolRunner{};
        const result = try driveGitRunner(gpa, io, &arbitrator, &inner, arguments);
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try testing.expectEqual(@as(usize, 1), arbitrator.asks);
        try testing.expectEqual(@as(usize, 1), inner.calls);
        try testing.expect(!result.is_error);
    }
}

test "a project with no chock.zon answers allow for git commit and ask for a push" {
    const gpa = testing.allocator;

    const empty: [:0]const u8 = ".{}";
    const policy = try chock_policy.table.Table.parse(gpa, empty, null);
    defer chock_policy.table.Table.destroy(gpa, policy);

    const key = struct {
        fn of(action: []const u8) chock_policy.table.Key {
            return .{
                .agent_kind = "main",
                .model = "test-model",
                .tool = "run_command",
                .action = action,
            };
        }
    };

    for ([_][]const u8{
        "git.add",
        "git.commit",
        "git.checkout",
        "git.branch",
        "git.branch.delete",
        "git.merge",
        "git.rebase",
        "git.reset",
        "git.stash",
        "git.worktree",
    }) |action| {
        try testing.expectEqual(
            chock_policy.table.Decision.allow,
            policy.evaluateKindAlone(key.of(action)),
        );
    }

    for ([_][]const u8{
        "git.push",
        "git.clone",
        "git.fetch",
        "git.pull",
        chock_broker.git_shim.unreadable_action,
        "git.frobnicate",
    }) |action| {
        try testing.expectEqual(
            chock_policy.table.Decision.ask,
            policy.evaluateKindAlone(key.of(action)),
        );
    }

    try testing.expectEqual(
        chock_policy.table.Decision.allow,
        policy.evaluateKindAlone(key.of("call.write_file")),
    );
    try testing.expectEqual(
        chock_policy.table.Decision.allow,
        policy.evaluateKindAlone(key.of("call.edit_file")),
    );
    try testing.expectEqual(
        chock_policy.table.Decision.ask,
        policy.evaluateKindAlone(key.of("file.write")),
    );
}

const StubToolRunner = struct {
    output: []const u8 = "wrote src/main.zig, 12 bytes, file_hash 0123456789abcdef\n",
    is_error: bool = false,
    calls: usize = 0,

    fn runner(self: *StubToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        _ = io;
        const self: *StubToolRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = try gpa.dupe(u8, self.output),
            .is_error = self.is_error,
            .truncated = false,
        };
    }
};

const StubServer = struct {
    diagnostic: chock_core.lsp.Diagnostic = .{
        .path = "src/main.zig",
        .line = 12,
        .column = 5,
        .severity = .err,
        .message = "expected type 'u8', found 'void'",
    },
    calls: usize = 0,

    fn server(self: *StubServer) chock_core.lsp.Server {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.lsp.Server.VTable{ .diagnose = diagnoseFn };

    fn diagnoseFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        ask: chock_core.lsp.Ask,
    ) std.mem.Allocator.Error!chock_core.lsp.Answer {
        _ = io;
        _ = ask;
        const self: *StubServer = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        const list = try arena.alloc(chock_core.lsp.Diagnostic, 1);
        list[0] = self.diagnostic;
        return .{ .reported = list };
    }
};

test "a write that worked carries what the language server said, on the same result" {
    const gpa = testing.allocator;

    for ([_][]const u8{ "write_file", "edit_file" }) |tool| {
        var inner = StubToolRunner{};
        var stub = StubServer{};
        var session = chock_core.lsp.Session{
            .program = "zls",
            .suffixes = &.{".zig"},
            .server = stub.server(),
        };
        var diagnosing = DiagnosticToolRunner{ .inner = inner.runner(), .session = &session };

        const result = try diagnosing.runner().dispatch(gpa, testing.io, .{
            .call_id = "call1",
            .tool = tool,
            .arguments = "{\"path\":\"src/main.zig\",\"content\":\"x\",\"old_string\":\"a\",\"new_string\":\"b\"}",
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try testing.expect(std.mem.startsWith(u8, result.output, "wrote src/main.zig"));
        try testing.expect(std.mem.indexOf(u8, result.output, "1 problem after this edit") != null);
        try testing.expect(std.mem.indexOf(u8, result.output, "src/main.zig:12:5: error:") != null);
        try testing.expectEqual(@as(usize, 1), stub.calls);
    }
}

test "a session with no language server hands back the tool result byte for byte" {
    const gpa = testing.allocator;

    var inner = StubToolRunner{};
    var session = chock_core.lsp.Session{};
    var diagnosing = DiagnosticToolRunner{ .inner = inner.runner(), .session = &session };

    const result = try diagnosing.runner().dispatch(gpa, testing.io, .{
        .call_id = "call1",
        .tool = "write_file",
        .arguments = "{\"path\":\"src/main.zig\",\"content\":\"x\"}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try testing.expectEqualStrings(inner.output, result.output);
    try testing.expect(!result.is_error);
}

test "a refused write and a call that is not a write are both passed straight through" {
    const gpa = testing.allocator;

    {
        var inner = StubToolRunner{
            .output = "old_string does not appear in src/main.zig, so nothing was written",
            .is_error = true,
        };
        var stub = StubServer{};
        var session = chock_core.lsp.Session{ .suffixes = &.{".zig"}, .server = stub.server() };
        var diagnosing = DiagnosticToolRunner{ .inner = inner.runner(), .session = &session };

        const result = try diagnosing.runner().dispatch(gpa, testing.io, .{
            .call_id = "call1",
            .tool = "edit_file",
            .arguments = "{\"path\":\"src/main.zig\",\"old_string\":\"a\",\"new_string\":\"b\"}",
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try testing.expectEqualStrings(inner.output, result.output);
        try testing.expect(result.is_error);
        try testing.expectEqual(@as(usize, 0), stub.calls);
    }

    for ([_][]const u8{ "read_file", "grep", "glob", "list_directory", "run_command" }) |tool| {
        var inner = StubToolRunner{ .output = "the tool's own answer" };
        var stub = StubServer{};
        var session = chock_core.lsp.Session{ .suffixes = &.{".zig"}, .server = stub.server() };
        var diagnosing = DiagnosticToolRunner{ .inner = inner.runner(), .session = &session };

        const result = try diagnosing.runner().dispatch(gpa, testing.io, .{
            .call_id = "call1",
            .tool = tool,
            .arguments = "{\"path\":\"src/main.zig\",\"pattern\":\"x\",\"argv\":[\"zig\",\"build\"]}",
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try testing.expectEqualStrings("the tool's own answer", result.output);
        try testing.expectEqual(@as(usize, 0), stub.calls);
    }
}

fn printedFor(gpa: std.mem.Allocator, events: []const chock_proto.event.Event) ![]u8 {
    var steps: std.ArrayList(PrinterStep) = .empty;
    defer steps.deinit(gpa);
    for (events) |ev| try steps.append(gpa, .{ .event = ev });
    return printedForSteps(gpa, steps.items);
}

const PrinterStep = union(enum) {
    event: chock_proto.event.Event,
    piece: chock_core.Loop.Piece,
};

fn printedForSteps(gpa: std.mem.Allocator, steps: []const PrinterStep) ![]u8 {
    return printedForStepsPainted(gpa, steps, .off);
}

fn printedForStepsPainted(
    gpa: std.mem.Allocator,
    steps: []const PrinterStep,
    paint: tty.Painter,
) ![]u8 {
    var shown: std.ArrayList(u8) = .empty;
    errdefer shown.deinit(gpa);
    var printer = Printer.init(gpa, testing.io);
    defer printer.deinit();
    printer.out = .{ .buffer = .{ .gpa = gpa, .bytes = &shown } };
    printer.paint = paint;
    const watcher = printer.observer();
    for (steps, 0..) |step, index| switch (step) {
        .event => |ev| watcher.onEvent(index, ev),
        .piece => |piece| watcher.onPiece(piece),
    };
    return shown.toOwnedSlice(gpa);
}

fn lineCount(text: []const u8) usize {
    if (text.len == 0) return 0;
    var seen = std.mem.count(u8, text, "\n");
    if (text[text.len - 1] != '\n') seen += 1;
    return seen;
}

test "a quiet start says less than a verbose one and still names every instruction file" {
    const gpa = testing.allocator;
    const loaded = chock_core.instructions.Loaded{ .files = &.{
        .{ .layer = .operator, .path = "/home/a/.config/chock/AGENTS.md", .bytes = 900 },
        .{ .layer = .project, .path = "AGENTS.md", .bytes = 4096 },
    } };

    var quiet: std.Io.Writer.Allocating = .init(gpa);
    defer quiet.deinit();
    var loud: std.Io.Writer.Allocating = .init(gpa);
    defer loud.deinit();

    defer tty.configure(.{});
    defer tty.useStreams(testing.io, null, null);

    tty.configure(.{ .verbose = false });
    tty.useStreams(testing.io, null, &quiet.writer);
    reportInstructions(loaded);

    tty.configure(.{ .verbose = true });
    tty.useStreams(testing.io, null, &loud.writer);
    reportInstructions(loaded);

    try testing.expect(lineCount(quiet.written()) < lineCount(loud.written()));
    try testing.expectEqual(@as(usize, 1), lineCount(quiet.written()));

    for (loaded.files) |file| {
        try testing.expect(std.mem.indexOf(u8, quiet.written(), file.path) != null);
    }
    try testing.expect(std.mem.indexOf(u8, quiet.written(), "4096 bytes") == null);
    try testing.expect(std.mem.indexOf(u8, loud.written(), "4096 bytes") != null);
}

test "a display opens on the conversation the log already holds" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var backing = try chock_proto.storage.Memory.init(gpa, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    defer backing.deinit();
    const store = backing.storage();

    var locked = try store.lock(io);
    _ = try locked.append(gpa, io, .{ .message = .{
        .role = .user,
        .content = &.{.{ .text = "fix the parser" }},
    } }, 0);
    _ = try locked.append(gpa, io, .{ .message = .{
        .role = .assistant,
        .content = &.{.{ .text = "the parser is where it fails" }},
    } }, 0);
    try locked.unlock(io);

    var frames: std.Io.Writer.Allocating = .init(gpa);
    defer frames.deinit();
    var said: std.Io.Writer.Allocating = .init(gpa);
    defer said.deinit();
    defer tty.useStreams(io, null, null);
    tty.useStreams(io, &frames.writer, &said.writer);
    defer tty.configure(.{});
    tty.configure(.{});

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    const device = try std.Io.Dir.openFileAbsolute(io, "/dev/null", .{});
    defer device.close(io);

    const screen = try ui.Ui.start(gpa, io, &env, .{ .terminal = .{
        .in = device,
        .out = device,
        .size = .{ .cols = 80, .rows = 24, .xpixel = 640, .ypixel = 384 },
    } });
    defer screen.deinit();

    replayInto(gpa, io, store, screen);

    var said_by_person = false;
    var said_by_model = false;
    for (screen.lines.items) |line| {
        if (std.mem.eql(u8, line.text, "fix the parser")) said_by_person = true;
        if (std.mem.eql(u8, line.text, "the parser is where it fails")) said_by_model = true;
    }
    try testing.expect(said_by_person);
    try testing.expect(said_by_model);

    try testing.expectEqualStrings("", screen.transcript.items);
}

const own_source = @embedFile("run.zig");

/// Each pattern opens with a real newline and the indent of the block, so it
/// matches the call itself and never the same words inside a comment. The bytes
/// written here hold a backslash and an `n`, so this file cannot match itself.
fn callAt(pattern: []const u8) error{CallIsGone}!usize {
    return std.mem.indexOf(u8, own_source, pattern) orelse error.CallIsGone;
}

test "an agent that has made no commit is answered before anything is put to anybody" {
    const counted = try callAt("\n            .output = try self.nothingCommitted(gpa, spawning_io, tree),");
    const asked = try callAt("\n        var carried = carryCommit(gpa, arena, spawning_io, .{");

    try testing.expect(counted < asked);

    const no_worktree = try callAt("\n            .overlay => return .{ .carried = false, .output = try gpa.dupe(");
    try testing.expect(no_worktree < counted);
}

test "every ending of an apply writes down what it did to the branch" {
    _ = try callAt("\n        recordIntegration(gpa, io, params.locked, started.apply_mode, params.ref, .{\n            .park = .{ .wanted = wanted.landing(), .why = .already_there },");
    _ = try callAt("\n            recordIntegration(gpa, io, params.locked, started.apply_mode, params.ref, .{\n                .park = .{ .wanted = wanted.landing(), .why = .apply_refused },");
    _ = try callAt("\n            recordIntegration(gpa, io, params.locked, started.apply_mode, params.ref, carried.integration);");

    const recorded = try callAt("\n            recordIntegration(gpa, io, params.locked, started.apply_mode, params.ref, carried.integration);");
    const answered = try callAt("\n            return .{ .landed = .{\n                .objects = carried.objects_moved,");
    try testing.expect(recorded < answered);
}

test "the log records the landing that happened, and not the mode the project configured" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const id = "01JQ" ++ "E" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);

    const log = try chock_proto.log.Log.open(io, log_path, id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    const asked_the_person = ApplyMode{ .mode = .ask, .decision = .allow, .asked_for = .ask };

    var locked = try store.lock(io);
    var branch = "refs/heads/main".*;
    var from = "1111111111111111111111111111111111111111".*;
    var to = "2222222222222222222222222222222222222222".*;
    recordIntegration(gpa, io, &locked, asked_the_person, "refs/chock/one", .{ .moved = .{
        .landing = .merge,
        .branch = &branch,
        .from = &from,
        .to = &to,
    } });
    recordIntegration(gpa, io, &locked, asked_the_person, "refs/chock/two", .{
        .park = .{ .wanted = .merge, .why = .dirty_tree },
    });
    recordIntegration(gpa, io, &locked, .{ .mode = null, .decision = .deny }, "refs/chock/three", .{
        .park = .{ .wanted = null, .why = .policy_refused },
    });
    try locked.unlock(io);

    const text = try std.Io.Dir.cwd().readFileAlloc(io, log_path, arena, .limited(1 << 20));
    if (std.mem.indexOf(u8, text, "\"mode\":\"ask\"") != null) {
        try std.testing.expectEqualStrings("no row saying the mode was ask", text);
        return error.TheRowRecordsThePlan;
    }
    try std.testing.expectEqual(
        @as(usize, 2),
        std.mem.count(u8, text, "\"mode\":\"merge\""),
    );
    try std.testing.expect(std.mem.indexOf(u8, text, "\"mode\":\"\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"decision\":\"allow\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"decision\":\"deny\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"parked\":\"dirty_tree\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"parked\":\"policy_refused\"") != null);
}

test "the line about a mode the policy took away is said again once the display is up" {
    const printed = try callAt(
        "\n    if (bounded == null) tty.print(.warn, \"chock: \" ++ bounded_mode_fmt",
    );
    const opened = try callAt("\n        screen = ui.Ui.start(gpa, io, env, wanted.attach) catch |err|");
    const said_again = try callAt(
        "\n        if (started.apply_mode.mode == null) one.note(",
    );

    try std.testing.expect(opened < said_again);
    try std.testing.expect(printed != said_again);
}

test "the display is told what the session is, then filled from the log, then asked for a message" {
    const described = try callAt("\n        one.describe(.{");
    const replayed = try callAt("\n        replayInto(gpa, io, started.storage, one);");
    const primed = try callAt("\n        if (options.display.?.first_message.len != 0) one.prime(");

    try testing.expect(described < replayed);
    try testing.expect(replayed < primed);
}

test "no startup line carries an escape sequence when the stream is not a terminal" {
    const gpa = testing.allocator;
    var shown: std.Io.Writer.Allocating = .init(gpa);
    defer shown.deinit();

    defer tty.configure(.{});
    defer tty.useStreams(testing.io, null, null);
    tty.configure(.{ .verbose = true, .stderr_is_tty = false, .term = "xterm-256color" });
    tty.useStreams(testing.io, null, &shown.writer);

    reportInstructions(.{
        .files = &.{.{ .layer = .project, .path = "AGENTS.md", .bytes = 4096 }},
        .subtrees_left_out = 3,
    });

    try testing.expect(shown.written().len != 0);
    try testing.expect(std.mem.indexOfScalar(u8, shown.written(), 0x1b) == null);
}

test "a printer that is not writing to a terminal emits no escape sequence at all" {
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{.{ .text = "the answer" }};
    const shown = try printedForSteps(gpa, &.{
        .{ .event = .{ .message = .{ .role = .system, .content = &content } } },
        .{ .event = .{ .tool_call = .{ .call_id = "1", .tool = "read_file", .arguments = "{}" } } },
        .{ .event = .{ .tool_result = .{ .call_id = "1", .output = "no such file", .is_error = true, .truncated = false } } },
        .{ .event = .{ .compaction = .{
            .summary = "what happened",
            .from_id = 1,
            .through_id = 2,
            .kept_ranges = &.{},
            .model_alias = "small",
        } } },
        .{ .event = .{ .message = .{ .role = .assistant, .content = &content } } },
        .{ .event = .{ .session_end = .{ .reason = .errored, .detail = "the provider hung up" } } },
    });
    defer gpa.free(shown);

    try testing.expect(shown.len != 0);
    try testing.expect(std.mem.indexOfScalar(u8, shown, 0x1b) == null);
}

test "a printer writing to a terminal paints a failed tool result and leaves the answer alone" {
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{.{ .text = "the answer" }};

    const failed = try printedForStepsPainted(gpa, &.{
        .{ .event = .{ .tool_result = .{ .call_id = "1", .output = "no such file", .is_error = true, .truncated = false } } },
    }, .colour);
    defer gpa.free(failed);
    try testing.expectEqualStrings("\x1b[31m! no such file\n\x1b[0m", failed);

    const worked = try printedForStepsPainted(gpa, &.{
        .{ .event = .{ .tool_result = .{ .call_id = "1", .output = "ok", .is_error = false, .truncated = false } } },
    }, .colour);
    defer gpa.free(worked);
    try testing.expectEqualStrings("ok\n", worked);

    const answer = try printedForStepsPainted(gpa, &.{
        .{ .event = .{ .message = .{ .role = .assistant, .content = &content } } },
    }, .colour);
    defer gpa.free(answer);
    try testing.expectEqualStrings("the answer\n", answer);
}

test "a result's note is written above the result, in Chock's own voice" {
    const gpa = testing.allocator;
    const shown = try printedForSteps(gpa, &.{
        .{ .event = .{ .tool_result = .{
            .call_id = "1",
            .output = "nothing was read: which you cannot write and the user can.",
            .is_error = true,
            .truncated = false,
            .note = "add a rule to chock.zon to read ziglang.org.",
        } } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings(
        "chock: add a rule to chock.zon to read ziglang.org.\n" ++
            "! nothing was read: which you cannot write and the user can.\n",
        shown,
    );

    const plain = try printedForSteps(gpa, &.{
        .{ .event = .{ .tool_result = .{ .call_id = "1", .output = "ok", .is_error = false, .truncated = false } } },
    });
    defer gpa.free(plain);
    try testing.expectEqualStrings("ok\n", plain);
}

test "a session that finished and one that did not are painted differently" {
    const gpa = testing.allocator;

    const clean = try printedForStepsPainted(gpa, &.{
        .{ .event = .{ .session_end = .{ .reason = .finished, .detail = "" } } },
    }, .colour);
    defer gpa.free(clean);

    const bad = try printedForStepsPainted(gpa, &.{
        .{ .event = .{ .session_end = .{ .reason = .budget_reached, .detail = "" } } },
    }, .colour);
    defer gpa.free(bad);

    try testing.expect(std.mem.startsWith(u8, clean, tty.Painter.colour.open(.dim)));
    try testing.expect(std.mem.startsWith(u8, bad, tty.Painter.colour.open(.warn)));
    try testing.expect(!std.mem.eql(u8, clean[0..4], bad[0..4]));
}

test "the answer is on the screen before the turn ends, and the event that closes the turn does not print it again" {
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{.{ .text = "Hello world" }};
    const shown = try printedForSteps(gpa, &.{
        .{ .piece = .{ .text = "Hello " } },
        .{ .piece = .{ .text = "world" } },
        .{ .event = .{ .message = .{ .role = .assistant, .content = &content } } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings("Hello world\n", shown);
}

test "what was streamed belongs to its own turn, and the next turn starts from nothing" {
    const gpa = testing.allocator;
    const first = [_]chock_proto.event.ContentPart{.{ .text = "first" }};
    const second = [_]chock_proto.event.ContentPart{.{ .text = "second" }};
    const shown = try printedForSteps(gpa, &.{
        .{ .piece = .{ .text = "first" } },
        .{ .event = .{ .message = .{ .role = .assistant, .content = &first } } },
        .{ .event = .{ .message = .{ .role = .assistant, .content = &second } } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings("first\nsecond\n", shown);
}

test "the model's reasoning is not printed as it arrives, so the answer is not buried in it" {
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{.{ .text = "42" }};
    const shown = try printedForSteps(gpa, &.{
        .{ .piece = .{ .reasoning = "counting on my fingers" } },
        .{ .piece = .{ .text = "42" } },
        .{ .event = .{ .message = .{ .role = .assistant, .content = &content } } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings("42\n", shown);
}

test "a turn that only reasoned prints nothing at all, and not a blank line" {
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{
        .{ .reasoning = .{ .text = "weighing the approach", .signature = "SIG==" } },
        .{ .tool_use = .{ .call_id = "toolu_1", .tool = "list_directory", .arguments = "{}" } },
    };
    const shown = try printedFor(gpa, &.{
        .{ .message = .{ .role = .assistant, .content = &content } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings("", shown);
}

test "a turn that said something keeps the newline that closes it" {
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{
        .{ .reasoning = .{ .text = "weighing the approach", .signature = "SIG==" } },
        .{ .text = "I will list the files." },
    };
    const shown = try printedFor(gpa, &.{
        .{ .message = .{ .role = .assistant, .content = &content } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings("I will list the files.\n", shown);
}

test "a reasoning only turn ahead of a tool call leaves one blank line and not two" {
    const gpa = testing.allocator;
    const thinking = [_]chock_proto.event.ContentPart{
        .{ .reasoning = .{ .text = "weighing the approach", .signature = "SIG==" } },
    };
    const answer = [_]chock_proto.event.ContentPart{.{ .text = "There are 4 entries." }};
    const shown = try printedFor(gpa, &.{
        .{ .message = .{ .role = .assistant, .content = &thinking } },
        .{ .tool_call = .{ .call_id = "toolu_1", .tool = "list_directory", .arguments = "{\"path\":\".\"}" } },
        .{ .tool_result = .{
            .call_id = "toolu_1",
            .output = "README.md",
            .is_error = false,
            .truncated = false,
        } },
        .{ .message = .{ .role = .assistant, .content = &answer } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings(
        \\
        \\$ list_directory {"path":"."}
        \\README.md
        \\There are 4 entries.
        \\
    , shown);
}

test "a user's own message is still not echoed, whatever the newline rule does" {
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{.{ .text = "list the files" }};
    const shown = try printedFor(gpa, &.{
        .{ .message = .{ .role = .user, .content = &content } },
    });
    defer gpa.free(shown);
    try testing.expectEqualStrings("", shown);
}

test "a compaction says so on the terminal, and says the log kept everything" {
    const gpa = testing.allocator;
    const shown = try printedFor(gpa, &.{
        .{ .compaction = .{
            .summary = "the parser work is half done",
            .from_id = 12,
            .through_id = 900,
            .kept_ranges = &.{},
            .model_alias = "local",
        } },
    });
    defer gpa.free(shown);

    try testing.expect(std.mem.indexOf(u8, shown, "folded into a summary") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "local") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "still in the session log") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "the parser work") == null);
}

test "what the harness tells the model reaches the user too" {
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{
        .{ .text = "[chock] Your context holds 40000 tokens of the 65536 this model can take" },
    };
    const shown = try printedFor(gpa, &.{
        .{ .message = .{ .role = .system, .content = &content } },
    });
    defer gpa.free(shown);

    try testing.expect(std.mem.indexOf(u8, shown, "40000 tokens") != null);
}

test "a whole plan update is one row, and it names the step being worked on" {
    const gpa = testing.allocator;
    const shown = try printedFor(gpa, &.{
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "s1", .subject = "read the fold", .status = .done },
            .{ .id = "s2", .subject = "write the command", .status = .in_progress },
            .{ .id = "s3", .subject = "measure it on Darwin", .status = .pending, .blocked_by = "s2" },
            .{ .id = "s4", .subject = "write the tests", .status = .pending },
        } } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings(
        "\nchock: plan: 1 of 4 done, now on \"write the command\"\n",
        shown,
    );
}

test "a step starting work moves no count and is still reported by name" {
    const gpa = testing.allocator;
    const shown = try printedFor(gpa, &.{
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "s1", .subject = "read the fold", .status = .pending },
            .{ .id = "s2", .subject = "write the command", .status = .pending },
        } } },
        .{ .plan_update = .{ .steps = &.{.{ .id = "s2", .subject = "", .status = .in_progress }} } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings(
        "\nchock: plan: 0 of 2 done\n" ++
            "\nchock: plan: 0 of 2 done, now on \"write the command\"\n",
        shown,
    );
}

test "a step given up keeps a row of its own, once, and rides the summary after" {
    const gpa = testing.allocator;
    const shown = try printedFor(gpa, &.{
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "s1", .subject = "read the fold", .status = .done },
            .{ .id = "s2", .subject = "write the command", .status = .pending },
            .{ .id = "s3", .subject = "measure it on Darwin", .status = .pending },
        } } },
        .{ .plan_update = .{ .steps = &.{.{ .id = "s3", .subject = "", .status = .abandoned }} } },
        .{ .plan_update = .{ .steps = &.{.{ .id = "s3", .subject = "", .status = .abandoned }} } },
    });
    defer gpa.free(shown);

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, shown, "was given up"));
    try testing.expect(std.mem.indexOf(
        u8,
        shown,
        "chock: plan step s3 was given up: measure it on Darwin\n",
    ) != null);
    try testing.expect(std.mem.endsWith(u8, shown, "\nchock: plan: 1 of 3 done, 1 given up\n"));
}

test "a promise the agent makes is printed as it is made, with the reason it gave" {
    const gpa = testing.allocator;
    const shown = try printedFor(gpa, &.{
        .{ .policy_self = .{ .restrictions = &.{.{
            .action = "net.fetch",
            .ceiling = .deny,
            .reason = "this task reads local files only",
        }} } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings(
        "\nchock: the agent promised net.fetch at most deny: this task reads local files only\n",
        shown,
    );

    const newer = try printedFor(gpa, &.{
        .{ .policy_self = .{ .restrictions = &.{.{
            .action = "git.*",
            .ceiling = .{ .unknown = "ask_two_people" },
            .reason = "",
        }} } },
    });
    defer gpa.free(newer);
    try testing.expectEqualStrings("\nchock: the agent promised git.* at most ask_two_people\n", newer);
}

const RecordingToolRunner = struct {
    context: *const chock_core.tools.Context,
    tool_env: *const std.process.Environ.Map,
    calls: usize = 0,
    last_store_paths: []const []const u8 = &.{},
    last_path: []const u8 = "",

    fn runner(self: *RecordingToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        _ = io;
        const self: *RecordingToolRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.last_store_paths = self.context.store_paths;
        self.last_path = self.tool_env.get("PATH") orelse "";
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = try gpa.dupe(u8, "ran"),
            .is_error = false,
            .truncated = false,
        };
    }
};

test "a program taken into the toolchain is mounted by the next tool call, and not by the one before" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    try tool_env.put("PATH", "/nix/store/aaa-coreutils/bin");

    var context = chock_core.tools.Context{ .store_paths = &.{"/nix/store/aaa-coreutils"} };
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var mounts = SessionMounts{
        .arena = arena_state.allocator(),
        .context = &context,
        .tool_env = &tool_env,
    };
    var provisioning = ProvisionToolRunner{
        .inner = recorder.runner(),
        .settings = null,
        .arena = arena_state.allocator(),
        .host_env = &tool_env,
        .environ = .empty,
        .mounts = &mounts,
    };
    try mounts.start(context.store_paths);
    const runner = provisioning.runner();

    const call = chock_proto.event.ToolCall{
        .call_id = "c1",
        .tool = "run_command",
        .arguments = "{\"argv\":[\"rg\"]}",
    };

    const before = try runner.dispatch(gpa, std.testing.io, call);
    gpa.free(before.call_id);
    gpa.free(before.output);
    try std.testing.expectEqual(@as(usize, 1), recorder.last_store_paths.len);
    try std.testing.expectEqualStrings("/nix/store/aaa-coreutils/bin", recorder.last_path);

    const store_paths = [_][]const u8{
        "/nix/store/bbb-ripgrep",
        "/nix/store/ccc-pcre2",
    };
    const bin_dirs = [_][]const u8{"/nix/store/bbb-ripgrep/bin"};
    try provisioning.adopt("ripgrep", .{
        .program = "ripgrep",
        .installable = "nixpkgs#ripgrep",
        .bin_dirs = &bin_dirs,
        .store_paths = &store_paths,
    });

    const after = try runner.dispatch(gpa, std.testing.io, call);
    gpa.free(after.call_id);
    gpa.free(after.output);
    try std.testing.expectEqual(@as(usize, 3), recorder.last_store_paths.len);
    try std.testing.expectEqualStrings("/nix/store/aaa-coreutils", recorder.last_store_paths[0]);
    try std.testing.expectEqualStrings("/nix/store/ccc-pcre2", recorder.last_store_paths[2]);
    try std.testing.expectEqualStrings(
        "/nix/store/bbb-ripgrep/bin:/nix/store/aaa-coreutils/bin",
        recorder.last_path,
    );

    try std.testing.expectEqual(@as(usize, 2), recorder.calls);
}

test "what a build produced is mounted by the next tool call, and not by the one before" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    try tool_env.put("PATH", "/nix/store/aaa-devshell/bin");

    var context = chock_core.tools.Context{ .store_paths = &.{"/nix/store/aaa-devshell"} };
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var mounts = SessionMounts{
        .arena = arena_state.allocator(),
        .context = &context,
        .tool_env = &tool_env,
    };
    try mounts.start(context.store_paths);

    var nix_build = NixBuildToolRunner{
        .inner = recorder.runner(),
        .settings = null,
        .arena = arena_state.allocator(),
        .host_env = &tool_env,
        .environ = .empty,
        .mounts = &mounts,
    };
    var provisioning = ProvisionToolRunner{
        .inner = nix_build.runner(),
        .settings = null,
        .arena = arena_state.allocator(),
        .host_env = &tool_env,
        .environ = .empty,
        .mounts = &mounts,
    };
    const runner = provisioning.runner();

    const call = chock_proto.event.ToolCall{
        .call_id = "c1",
        .tool = "run_command",
        .arguments = "{\"argv\":[\"myproject\"]}",
    };

    const before = try runner.dispatch(gpa, std.testing.io, call);
    gpa.free(before.call_id);
    gpa.free(before.output);
    try std.testing.expectEqual(@as(usize, 1), recorder.last_store_paths.len);

    const closure = [_][]const u8{ "/nix/store/aaa-devshell", "/nix/store/bbb-myproject" };
    try mounts.adopt(.{
        .program = "/work#packages.x86_64-linux.default",
        .installable = "/work#packages.x86_64-linux.default",
        .bin_dirs = &.{"/nix/store/bbb-myproject/bin"},
        .store_paths = &closure,
    });

    const after = try runner.dispatch(gpa, std.testing.io, call);
    gpa.free(after.call_id);
    gpa.free(after.output);

    try std.testing.expectEqual(@as(usize, 2), recorder.last_store_paths.len);
    try std.testing.expectEqualStrings("/nix/store/bbb-myproject", recorder.last_store_paths[1]);
    try std.testing.expectEqualStrings(
        "/nix/store/bbb-myproject/bin:/nix/store/aaa-devshell/bin",
        recorder.last_path,
    );
    try std.testing.expectEqual(@as(usize, 2), recorder.calls);
}

test "a host a Nix build would fetch from is named under nix.net.build, labels reversed" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var gate = NixFetchGate{
        .gpa = gpa,
        .io = std.testing.io,
        .asker = null,
        .installable = "/work#packages.x86_64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
    };

    const said = (try gate.gate().permitAll(arena, &.{.{
        .subject = "b-src.drv",
        .url = "https://files.example.com/src.tar.gz",
        .host = "files.example.com",
        .port = 443,
    }})).refused;
    try std.testing.expect(
        std.mem.indexOf(u8, said, "nix.net.build.com.example.files.443") != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, said, "net.connect") == null);
    try std.testing.expect(std.mem.indexOf(u8, said, "b-src.drv") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "files.example.com") != null);

    const hostile = (try gate.gate().permitAll(arena, &.{.{
        .subject = "c-src.drv",
        .url = "https://evil.com.example.files/x",
        .host = "evil.com.example.files",
        .port = 443,
    }})).refused;
    try std.testing.expect(
        std.mem.indexOf(u8, hostile, "nix.net.build.files.example.com.evil.443") != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, hostile, "nix.net.build.com.example.") == null);

    const unnameable = (try gate.gate().permitAll(arena, &.{.{
        .subject = "d-src.drv",
        .url = "https://a_b/x",
        .host = "a_b",
        .port = 443,
    }})).refused;
    try std.testing.expect(std.mem.indexOf(u8, unnameable, "nix.net") == null);
    try std.testing.expect(std.mem.indexOf(u8, unnameable, "d-src.drv") != null);
}

test "an input fetch is named under nix.net.eval, and the same host reads differently in each phase" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var input_gate = NixFetchGate{
        .gpa = gpa,
        .io = std.testing.io,
        .asker = null,
        .installable = "/work#packages.x86_64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
        .kind = .flake_input,
    };

    const said = (try input_gate.gate().permitAll(arena, &.{.{
        .subject = "nixpkgs",
        .url = "https://api.github.com",
        .host = "api.github.com",
        .port = 443,
    }})).refused;
    try std.testing.expect(
        std.mem.indexOf(u8, said, "nix.net.eval.com.github.api.443") != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, said, "nix.net.build.") == null);
}

test "a build that fetches with no url is asked under fixed segments, and the words name it" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var gate = NixFetchGate{
        .gpa = gpa,
        .io = std.testing.io,
        .asker = null,
        .installable = "/work#packages.aarch64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
    };

    const said = (try gate.gate().permitOpaque(arena, &.{
        "chock-0.1.0-zig-deps.drv",
        "furo-web-2025.12.19-npm-deps.drv",
    })).refused;
    try std.testing.expect(std.mem.indexOf(u8, said, "nix.net.build.opaque") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "zig-deps") == null);
    try std.testing.expect(std.mem.indexOf(u8, said, "net.connect") == null);
    try std.testing.expectEqualStrings("nix.net.build.opaque", NixFetchGate.opaque_action);
}

test "a flake input host is asked of the policy table at startup, and ask is off there" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const allowing = try chock_policy.table.Table.parse(
        arena,
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "nix.net.eval.com.github.api.443", .decision = .allow },
        \\        },
        \\    },
        \\}
    ,
        null,
    );
    var gate = StartupFetchGate{
        .policy = allowing,
        .chain = &.{"agent"},
        .agent_kind = "agent",
        .model = "test-model",
    };
    const wanted = chock_nix.fetch.Fetch{
        .subject = "nixpkgs",
        .url = "https://api.github.com",
        .host = "api.github.com",
        .port = 443,
    };
    try std.testing.expect(try gate.gate().permitAll(arena, &.{wanted}) == .permitted);

    const quiet = try chock_policy.table.Table.parse(arena, ".{}", null);
    var silent = StartupFetchGate{
        .policy = quiet,
        .chain = &.{"agent"},
        .agent_kind = "agent",
        .model = "test-model",
    };
    const said = (try silent.gate().permitAll(arena, &.{wanted})).refused;
    try std.testing.expect(std.mem.indexOf(u8, said, "nixpkgs") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "api.github.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "nix.net.eval.com.github.api.443") != null);
}

test "a startup refusal is not a permanent no, and a build asks about the input it wanted" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var input_gate = NixFetchGate{
        .gpa = gpa,
        .io = std.testing.io,
        .asker = null,
        .installable = "/work#packages.aarch64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
        .kind = .flake_input,
    };
    const wanted = chock_nix.fetch.Fetch{
        .subject = "flakever",
        .url = "https://api.github.com",
        .host = "api.github.com",
        .port = 443,
    };

    const said = (try input_gate.gate().permitAll(arena, &.{wanted})).refused;
    try std.testing.expect(std.mem.indexOf(u8, said, "flake input flakever") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "api.github.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "nix.net.eval.com.github.api.443") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "while it builds") == null);

    const refusal = try chock_nix.inputs.missingRefusal(
        gpa,
        "/work#packages.aarch64-linux.default",
        said,
        &.{wanted},
    );
    defer gpa.free(refusal);
    try std.testing.expect(std.mem.indexOf(u8, refusal, "443 The inputs") == null);
    try std.testing.expect(std.mem.indexOf(u8, refusal, "flakever from api.github.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, refusal, "ask the user") == null);
}

test "a build whose inputs arrived at startup never reaches the question" {
    var budget: chock_nix.build.Budget = .{};
    var nowhere = NowhereWriter{};
    var writing = chock_nix.build.Writing{
        .writer = nowhere.writer(),
        .budget = &budget,
        .fetched_paths = &.{"/nix/store/aaaa-source"},
    };
    const seam = writing.seam();

    try std.testing.expect(try seam.vtable.is_valid_path.?(seam.context, "/nix/store/aaaa-source"));
    try std.testing.expect(!try seam.vtable.is_valid_path.?(seam.context, "/nix/store/bbbb-source"));
}

const NowhereWriter = struct {
    fn writer(self: *NowhereWriter) chock_nix.build.StoreWriter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: chock_nix.build.StoreWriter.VTable = .{ .add_object = addObject };

    fn addObject(
        _: *anyopaque,
        allocator: std.mem.Allocator,
        object: chock_nix.backend.AddObject,
    ) anyerror![]u8 {
        return allocator.dupe(u8, object.expectedPath());
    }
};

test "nix_build builds this project and refuses a flake reference that is not it" {
    const gpa = std.testing.allocator;

    try std.testing.expect(isWorkspaceFlake("/work", "/work"));
    try std.testing.expect(isWorkspaceFlake("/work", "/work/sub"));
    try std.testing.expect(!isWorkspaceFlake("/work", "/workspace"));
    try std.testing.expect(!isWorkspaceFlake("/work", "github:NixOS/nixpkgs"));

    const said = try foreignFlakeRefusal(gpa, "github:NixOS/nixpkgs");
    defer gpa.free(said);
    try std.testing.expect(std.mem.indexOf(u8, said, "github:NixOS/nixpkgs") != null);
}

test "a program out of a build asks under exec.nix.store, and the dev shell's own still asks under exec.devshell" {
    const startup_closure = [_][]const u8{"/nix/store/aaa-devshell"};

    var buffer: [chock_core.tools.Tool.max_action_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "exec.devshell.aaa-devshell.bin.zig",
        chock_core.tools.Tool.run_command.actionInto(
            &buffer,
            "/nix/store/aaa-devshell/bin/zig",
            "",
            &startup_closure,
        ).?,
    );

    var built_buffer: [chock_core.tools.Tool.max_action_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "exec.nix.store.bbb-myproject.bin.myproject",
        chock_core.tools.Tool.run_command.actionInto(
            &built_buffer,
            "/nix/store/bbb-myproject/bin/myproject",
            "",
            &startup_closure,
        ).?,
    );
}

test "a session that cannot provision refuses the call and names no package manager as a way out" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();

    var context = chock_core.tools.Context{};
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var mounts = SessionMounts{
        .arena = arena_state.allocator(),
        .context = &context,
        .tool_env = &tool_env,
    };
    var provisioning = ProvisionToolRunner{
        .inner = recorder.runner(),
        .settings = null,
        .arena = arena_state.allocator(),
        .host_env = &tool_env,
        .environ = .empty,
        .mounts = &mounts,
    };

    const result = try provisioning.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "c1",
        .tool = "provide_tool",
        .arguments = "{\"program\":\"ripgrep\"}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expect(result.is_error);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "cannot add one") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "apt") != null);
    try std.testing.expectEqual(@as(usize, 0), recorder.calls);
}

fn testNixEvalRunner(
    inner: chock_core.Loop.ToolRunner,
    root: []const u8,
    caps: chock_policy.nix.Resolved,
) NixEvalToolRunner {
    return .{ .inner = inner, .settings = .{ .workspace_root = root, .caps = caps } };
}

const default_nix_caps = chock_policy.nix.Resolved{
    .max_object_bytes = chock_policy.nix.default_max_object_bytes,
    .max_session_bytes = chock_policy.nix.default_max_session_bytes,
};

fn evaluateThrough(
    gpa: std.mem.Allocator,
    runner: *NixEvalToolRunner,
    expression: []const u8,
) !chock_proto.event.ToolResult {
    const arguments = try std.json.Stringify.valueAlloc(
        gpa,
        .{ .expression = expression },
        .{},
    );
    defer gpa.free(arguments);
    return runner.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "c1",
        .tool = "nix_eval",
        .arguments = arguments,
    });
}

test "an expression is evaluated in this process and the rendered value reaches the model" {
    const gpa = std.testing.allocator;

    var context = chock_core.tools.Context{};
    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var nix_eval = testNixEvalRunner(recorder.runner(), "/nowhere", default_nix_caps);

    const result = try evaluateThrough(gpa, &nix_eval, "{ a = 1; b = \"two\"; }");
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expect(!result.is_error);
    try std.testing.expectEqualStrings("{ a = 1; b = \"two\"; }", result.output);
    try std.testing.expectEqual(@as(usize, 0), recorder.calls);
}

test "a derivation answers its derivation path, and says that nothing was built" {
    const gpa = std.testing.allocator;

    var context = chock_core.tools.Context{};
    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var nix_eval = testNixEvalRunner(recorder.runner(), "/nowhere", default_nix_caps);

    const result = try evaluateThrough(gpa, &nix_eval,
        \\derivation { name = "x"; builder = "/bin/sh"; system = "x86_64-linux"; }
    );
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expect(!result.is_error);
    try std.testing.expect(std.mem.indexOf(
        u8,
        result.output,
        "/nix/store/97qlv6h78lxlm9zc8849ahsbcklhsi2y-x.drv",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "is a derivation") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "never builds") != null);
}

test "import from derivation is refused, and the refusal names the derivation" {
    const gpa = std.testing.allocator;

    var context = chock_core.tools.Context{};
    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var nix_eval = testNixEvalRunner(recorder.runner(), "/nowhere", default_nix_caps);

    const result = try evaluateThrough(gpa, &nix_eval,
        \\import (derivation { name = "y"; builder = "/bin/sh"; system = "x86_64-linux"; })
    );
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expect(result.is_error);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "-y.drv") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "drvPath") != null);
}

test "an expression that reads a path outside the workspace is refused" {
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var file = try tmp.dir.createFile(std.testing.io, "note.txt", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "hello");
    }
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try tmp.dir.realPath(std.testing.io, &root_buffer)];

    var context = chock_core.tools.Context{};
    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var nix_eval = testNixEvalRunner(recorder.runner(), root, default_nix_caps);

    const inside = try std.fmt.allocPrint(gpa, "builtins.readFile {s}/note.txt", .{root});
    defer gpa.free(inside);
    const read = try evaluateThrough(gpa, &nix_eval, inside);
    defer gpa.free(read.call_id);
    defer gpa.free(read.output);
    try std.testing.expect(!read.is_error);
    try std.testing.expectEqualStrings("\"hello\"", read.output);

    const outside = try evaluateThrough(gpa, &nix_eval, "builtins.readFile /etc/hostname");
    defer gpa.free(outside.call_id);
    defer gpa.free(outside.output);
    try std.testing.expect(outside.is_error);
    try std.testing.expect(std.mem.indexOf(u8, outside.output, root) != null);
}

test "the object cap a project names reaches the driver an evaluation answers through" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project_tmp = std.testing.tmpDir(.{});
    defer project_tmp.cleanup();
    var config_tmp = std.testing.tmpDir(.{});
    defer config_tmp.cleanup();

    {
        var file = try project_tmp.dir.createFile(io, chock_policy.limits.file_name, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, ".{ .nix = .{ .max_object_bytes = \"4KiB\" } }");
    }
    {
        var file = try config_tmp.dir.createFile(io, chock_policy.limits.operator_file_name, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, ".{ .nix = .{ .max_session_bytes = \"8MiB\" } }");
    }

    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_len = try project_tmp.dir.realPath(io, &project_buffer);
    var config_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const config_len = try config_tmp.dir.realPath(io, &config_buffer);

    const resolved = try resolveNixCaps(
        arena,
        io,
        project_buffer[0..project_len],
        config_buffer[0..config_len],
        null,
    );
    try std.testing.expectEqual(@as(u64, 4 << 10), resolved.max_object_bytes);
    try std.testing.expectEqual(@as(u64, 8 << 20), resolved.max_session_bytes);

    const settings = NixEval{ .workspace_root = "/nowhere", .caps = resolved };
    var driver = settings.driverFor(gpa);
    defer driver.deinit();
    try std.testing.expectEqual(@as(usize, 4 << 10), driver.max_object_bytes);

    const quiet = NixEval{ .workspace_root = "/nowhere", .caps = default_nix_caps };
    var quiet_driver = quiet.driverFor(gpa);
    defer quiet_driver.deinit();
    try std.testing.expectEqual(
        chock_nix.backend.default_max_object_bytes,
        quiet_driver.max_object_bytes,
    );
}

test "nix_eval answers through a store that takes no object, so it writes nothing to the host store" {
    const gpa = std.testing.allocator;

    const settings = NixEval{ .workspace_root = "/nowhere", .caps = default_nix_caps };
    var driver = settings.driverFor(gpa);
    defer driver.deinit();
    try std.testing.expect(driver.seam.vtable.add_object == null);
    try std.testing.expect(driver.seam.vtable.build_paths == null);

    try std.testing.expect(driver.seam.vtable.read_file == null);
}

test "a nix block that does not parse stops the session rather than evaluating under another number" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var project_tmp = std.testing.tmpDir(.{});
    defer project_tmp.cleanup();
    var config_tmp = std.testing.tmpDir(.{});
    defer config_tmp.cleanup();

    {
        var file = try project_tmp.dir.createFile(io, chock_policy.limits.file_name, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, ".{ .nix = .{ .max_object_bytes = \"50%\" } }");
    }

    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_len = try project_tmp.dir.realPath(io, &project_buffer);
    var config_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const config_len = try config_tmp.dir.realPath(io, &config_buffer);

    try std.testing.expectError(error.Reported, resolveNixCaps(
        arena,
        io,
        project_buffer[0..project_len],
        config_buffer[0..config_len],
        null,
    ));

    try std.testing.expect(std.mem.indexOf(u8, said.err(), "chock.zon") != null);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "max_object_bytes") != null);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "50%") != null);
}

test "a session that cannot evaluate refuses the call and never says it evaluated" {
    const gpa = std.testing.allocator;

    var context = chock_core.tools.Context{};
    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var nix_eval = NixEvalToolRunner{ .inner = recorder.runner(), .settings = null };

    const result = try evaluateThrough(gpa, &nix_eval, "1 + 1");
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expect(result.is_error);
    try std.testing.expectEqualStrings(nix_eval_is_off, result.output);
    try std.testing.expectEqual(@as(usize, 0), recorder.calls);

    const other = try nix_eval.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "c2",
        .tool = "read_file",
        .arguments = "{\"path\":\"a\"}",
    });
    defer gpa.free(other.call_id);
    defer gpa.free(other.output);
    try std.testing.expectEqual(@as(usize, 1), recorder.calls);
}

test "the tool is offered only to a session that can evaluate" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const without = try chock_core.tools.Registry.definitions(arena, .{
        .adapter = .openai_compatible,
    });
    for (without) |def| try std.testing.expect(!std.mem.eql(u8, def.name, "nix_eval"));

    const with = try chock_core.tools.Registry.definitions(arena, .{
        .adapter = .openai_compatible,
        .nix_eval = true,
    });
    var saw = false;
    for (with) |def| {
        if (std.mem.eql(u8, def.name, "nix_eval")) saw = true;
    }
    try std.testing.expect(saw);
}

test "asking twice for the same program builds nothing the second time" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    try tool_env.put("PATH", "/nix/store/aaa/bin");

    var context = chock_core.tools.Context{};
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var mounts = SessionMounts{
        .arena = arena_state.allocator(),
        .context = &context,
        .tool_env = &tool_env,
    };
    var provisioning = ProvisionToolRunner{
        .inner = recorder.runner(),
        .settings = .{
            .nix_program = "/nowhere/nix",
            .nix_store_program = null,
            .registry = "nixpkgs",
            .root_dir = null,
        },
        .arena = arena_state.allocator(),
        .host_env = &tool_env,
        .environ = .empty,
        .mounts = &mounts,
    };
    try provisioning.adopt("ripgrep", .{
        .program = "ripgrep",
        .installable = "nixpkgs#ripgrep",
        .bin_dirs = &.{},
        .store_paths = &.{},
    });

    const result = try provisioning.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "c1",
        .tool = "provide_tool",
        .arguments = "{\"program\":\"ripgrep\"}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expect(!result.is_error);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "already in this session") != null);
}

test "the policy key is the broker's own nix.build, and a project that said nothing cannot provision" {
    try std.testing.expectEqualStrings("nix.build", provision_action);

    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const empty = try chock_policy.table.Table.parse(arena, ".{}", null);
    defer chock_policy.table.Table.destroy(arena, empty);
    try std.testing.expectEqual(
        chock_policy.table.Decision.ask,
        try provisionDecision(arena, empty, &.{}, "main", "a-model"),
    );

    const allowed = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "nix.build", .decision = .allow },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, allowed);
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        try provisionDecision(arena, allowed, &.{}, "main", "a-model"),
    );

    const child_only = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .agent_kind = "reviewer", .action = "nix.build", .decision = .allow },
        \\    .{ .agent_kind = "main", .action = "nix.build", .decision = .deny },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, child_only);
    const chain = [_]chock_proto.event.SpawnLink{.{ .agent_kind = "main", .reason = "review it" }};
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        try provisionDecision(arena, child_only, &chain, "reviewer", "a-model"),
    );
}

test "the write and execute rule is on unless this project's policy says allow" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try std.testing.expectEqualStrings("sandbox.jit", chock_policy.hardening.jit_action);

    var said: tty.Capture = undefined;
    said.start(std.testing.io, gpa);
    defer said.stop(std.testing.io);

    const empty = try chock_policy.table.Table.parse(arena, ".{}", null);
    defer chock_policy.table.Table.destroy(arena, empty);
    const kept = try hardeningDecision(arena, empty, &.{}, "main", "a-model");
    try std.testing.expectEqual(chock_policy.table.Decision.ask, kept.decision);
    try std.testing.expectEqual(chock_policy.hardening.WriteExecute.strict, kept.rule);
    try std.testing.expectEqualStrings("", said.err());

    const allowed = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "sandbox.jit", .decision = .allow },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, allowed);
    const given_up = try hardeningDecision(arena, allowed, &.{}, "main", "a-model");
    try std.testing.expectEqual(chock_policy.hardening.WriteExecute.relaxed, given_up.rule);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "sandbox.jit") != null);
    try std.testing.expectEqualStrings("", said.out());

    said.clear();
    const org_rules = [_]chock_policy.table.Rule{
        .{ .action = chock_policy.hardening.jit_action, .decision = .deny },
    };
    const under_org = try chock_policy.table.Table.parseUnder(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "sandbox.jit", .decision = .allow },
        \\} } }
    , &org_rules, null);
    defer chock_policy.table.Table.destroy(arena, under_org);
    const refused = try hardeningDecision(arena, under_org, &.{}, "main", "a-model");
    try std.testing.expectEqual(chock_policy.table.Decision.deny, refused.decision);
    try std.testing.expectEqual(chock_policy.hardening.WriteExecute.strict, refused.rule);
    try std.testing.expectEqualStrings("", said.err());

    const child_only = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .agent_kind = "reviewer", .action = "sandbox.jit", .decision = .allow },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, child_only);
    const chain = [_]chock_proto.event.SpawnLink{.{ .agent_kind = "main", .reason = "review it" }};
    const child = try hardeningDecision(arena, child_only, &chain, "reviewer", "a-model");
    try std.testing.expectEqual(chock_policy.hardening.WriteExecute.strict, child.rule);
}

test "the mode comes from chock.zon and the table above it, and nothing configured merges" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try std.testing.expectEqualStrings("workspace.integrate", chock_policy.apply.integrate_action);

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    const empty = try chock_policy.table.Table.parse(arena, ".{}", null);
    defer chock_policy.table.Table.destroy(arena, empty);

    const silent = try applyModeFor(arena, io, root, empty, &.{}, "main", "a-model");
    try std.testing.expectEqual(@as(?chock_policy.apply.Mode, .merge), silent.mode);
    try std.testing.expectEqual(chock_policy.table.Decision.allow, silent.decision);
    try std.testing.expectEqualStrings("", said.err());

    try std.testing.expectEqual(
        chock_broker.integrate.Wanted{ .land = .merge },
        chosenLanding(gpa, io, silent.mode, null),
    );

    const zon_path = try std.fs.path.join(arena, &.{ root, "chock.zon" });
    var file = try std.Io.Dir.createFileAbsolute(io, zon_path, .{});
    try file.writeStreamingAll(io, ".{ .apply = .{ .mode = .merge } }\n");
    file.close(io);

    const asked = try applyModeFor(arena, io, root, empty, &.{}, "main", "a-model");
    try std.testing.expectEqual(@as(?chock_policy.apply.Mode, .merge), asked.mode);
    try std.testing.expectEqual(chock_policy.table.Decision.allow, asked.decision);
    try std.testing.expectEqualStrings("", said.err());

    said.clear();
    const org_rules = [_]chock_policy.table.Rule{
        .{ .action = chock_policy.apply.integrate_action, .decision = .deny },
    };
    const under_org = try chock_policy.table.Table.parseUnder(arena, ".{}", &org_rules, null);
    defer chock_policy.table.Table.destroy(arena, under_org);

    const refused = try applyModeFor(arena, io, root, under_org, &.{}, "main", "a-model");
    try std.testing.expectEqual(@as(?chock_policy.apply.Mode, null), refused.mode);
    try std.testing.expectEqual(chock_policy.table.Decision.deny, refused.decision);
    try std.testing.expectEqual(
        chock_broker.integrate.Wanted{ .none = .policy_refused },
        chosenLanding(gpa, io, refused.mode, null),
    );
    try std.testing.expectEqual(chock_policy.apply.Mode.merge, refused.asked_for);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "workspace.integrate") != null);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "merge") != null);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "chock.zon") == null);

    said.clear();
    const child_only = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .agent_kind = "reviewer", .action = "workspace.integrate", .decision = .deny },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, child_only);
    const chain = [_]chock_proto.event.SpawnLink{.{ .agent_kind = "main", .reason = "review it" }};
    const child = try applyModeFor(arena, io, root, child_only, &chain, "reviewer", "a-model");
    try std.testing.expectEqual(@as(?chock_policy.apply.Mode, null), child.mode);
    try std.testing.expectEqual(
        chock_broker.integrate.Wanted{ .none = .policy_refused },
        chosenLanding(gpa, io, child.mode, null),
    );
}

test "only a landing word moves a branch, whichever way the answer arrived" {
    const gpa = std.testing.allocator;

    for ([_][]const u8{ "merge", "rebase", "squash" }) |word| {
        const said = try gpa.dupe(u8, word);
        defer gpa.free(said);
        try std.testing.expectEqualStrings(
            word,
            landingFor(.{ .answered = said }).?.wireName(),
        );
    }

    const padded = try gpa.dupe(u8, " merge\r\n");
    defer gpa.free(padded);
    try std.testing.expectEqual(chock_policy.apply.Landing.merge, landingFor(.{ .answered = padded }));

    const nonsense = try gpa.dupe(u8, "yes please");
    defer gpa.free(nonsense);
    const Landing = chock_policy.apply.Landing;
    try std.testing.expectEqual(@as(?Landing, null), landingFor(.{ .answered = nonsense }));
    for ([_]chock_core.ask.Answer{ .declined, .nobody, .timed_out, .stopped }) |none| {
        try std.testing.expectEqual(@as(?Landing, null), landingFor(none));
    }
    const old_word = try gpa.dupe(u8, "ref");
    defer gpa.free(old_word);
    try std.testing.expectEqual(@as(?Landing, null), landingFor(.{ .answered = old_word }));
    for (landing_options) |option| {
        try std.testing.expect(!std.mem.eql(u8, "ref", option));
    }
}

test "a session with nobody at the keyboard never lands the work on a branch by itself" {
    const io = std.testing.io;
    const nobody = chosenLanding(std.testing.allocator, io, .ask, null);
    try std.testing.expectEqual(@as(?chock_policy.apply.Landing, null), nobody.landing());
    try std.testing.expectEqual(chock_broker.integrate.Reason.nobody_answered, nobody.none);

    const refused = chosenLanding(std.testing.allocator, io, null, null);
    try std.testing.expectEqual(@as(?chock_policy.apply.Landing, null), refused.landing());
    try std.testing.expectEqual(chock_broker.integrate.Reason.policy_refused, refused.none);

    for ([_]chock_policy.apply.Mode{ .merge, .rebase, .squash }) |mode| {
        try std.testing.expectEqualStrings(
            mode.wireName(),
            chosenLanding(std.testing.allocator, io, mode, null).landing().?.wireName(),
        );
    }
}

test "the log says which sandbox one attempt ran under, and it says it either way" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const dir = buffer[0..len];

    const id = "01JQ" ++ "C" ** 22;
    const attempt = "01JQ" ++ "D" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);

    const log = try chock_proto.log.Log.open(io, log_path, id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    try recordSandbox(gpa, io, store, attempt, .{ .decision = .ask, .rule = .strict });
    try recordSandbox(gpa, io, store, attempt, .{ .decision = .allow, .rule = .relaxed });

    const text = try std.Io.Dir.cwd().readFileAlloc(io, log_path, arena, .limited(1 << 20));
    try std.testing.expect(std.mem.indexOf(u8, text, "sandbox.open") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"write_execute\":\"strict\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"write_execute\":\"relaxed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"decision\":\"allow\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, attempt) != null);
}

test "a project with no devices block builds no seam, no host, and names no tree" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const empty = try chock_policy.table.Table.parse(arena, ".{}", null);
    defer chock_policy.table.Table.destroy(arena, empty);

    const wiring = try devicesFor(arena, gpa, std.testing.io, empty, &.{}, "main", "a-model", null);
    try std.testing.expectEqual(@as(?*DevicePolicySeam, null), wiring.seam);
    try std.testing.expectEqual(@as(?*chock_core.devices.HostSource, null), wiring.host);
    try std.testing.expectEqual(@as(?sandbox.Config.DeviceTree, null), wiring.device_tree);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/01JQ.jsonl", .{buffer[0..len]}, 0);
    const log = try chock_proto.log.Log.open(std.testing.io, log_path, "01JQ");
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(std.testing.io);

    try recordDevices(gpa, std.testing.io, store, "01JQATTEMPT", wiring.seam);
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, log_path, arena, .limited(1 << 20));
    try std.testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, text, "device.exposed"));
}

test "a named device whose rule says allow reaches the sandbox config" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const allowed = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "device.usb.1d50.6018", .tool = "device", .decision = .allow },
        \\    .{ .action = "device.*", .decision = .allow },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, allowed);

    const declared: []const chock_core.devices.Settings = &.{
        .{ .action = "device.usb.1d50.6018" },
    };
    const wiring = try devicesFor(arena, gpa, std.testing.io, allowed, &.{}, "main", "a-model", declared);
    defer if (wiring.host) |host| host.deinit();

    const seam = wiring.seam.?;
    try std.testing.expectEqual(chock_policy.table.Decision.allow, seam.decisionFor("device.usb.1d50.6018"));
    try std.testing.expect(seam.seam().permitted("device.usb.1d50.6018"));

    if (sandbox.expresses.device_passthrough) {
        try std.testing.expect(wiring.host != null);
        try std.testing.expectEqualStrings("/dev", wiring.device_tree.?.host);
        try std.testing.expectEqualStrings("/.chock-device-tree", wiring.device_tree.?.inside);
    } else {
        try std.testing.expectEqual(@as(?*chock_core.devices.HostSource, null), wiring.host);
        try std.testing.expectEqual(@as(?sandbox.Config.DeviceTree, null), wiring.device_tree);
    }

    try std.testing.expect(!seam.seam().permitted("device.usb.dead.beef"));
}

test "a named device with no policy rule answers ask, is refused, and says to write a rule" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(std.testing.io, gpa);
    defer said.stop(std.testing.io);

    const no_rule = try chock_policy.table.Table.parse(arena, ".{}", null);
    defer chock_policy.table.Table.destroy(arena, no_rule);

    const declared: []const chock_core.devices.Settings = &.{
        .{ .action = "device.tty.serial.DF62585783282137" },
    };
    const wiring = try devicesFor(arena, gpa, std.testing.io, no_rule, &.{}, "main", "a-model", declared);
    defer if (wiring.host) |host| host.deinit();

    const seam = wiring.seam.?;
    try std.testing.expectEqual(chock_policy.table.Decision.ask, seam.decisionFor("device.tty.serial.DF62585783282137"));
    try std.testing.expect(!seam.seam().permitted("device.tty.serial.DF62585783282137"));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/01JQ.jsonl", .{buffer[0..len]}, 0);
    const log = try chock_proto.log.Log.open(std.testing.io, log_path, "01JQ");
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(std.testing.io);

    try recordDevices(gpa, std.testing.io, store, "01JQATTEMPT", wiring.seam);

    try std.testing.expect(std.mem.indexOf(u8, said.err(), "device.tty.serial.DF62585783282137") != null);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "policy.rules") != null);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "allow") != null);
}

test "an org bundle that denies a device wins even when the project itself allows it" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const org_rules = [_]chock_policy.table.Rule{
        .{ .action = "device.usb.1d50.6018", .tool = "device", .decision = .deny },
    };
    const under_org = try chock_policy.table.Table.parseUnder(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "device.usb.1d50.6018", .tool = "device", .decision = .allow },
        \\} } }
    , &org_rules, null);
    defer chock_policy.table.Table.destroy(arena, under_org);

    const declared: []const chock_core.devices.Settings = &.{
        .{ .action = "device.usb.1d50.6018" },
    };
    const wiring = try devicesFor(arena, gpa, std.testing.io, under_org, &.{}, "main", "a-model", declared);
    defer if (wiring.host) |host| host.deinit();

    try std.testing.expectEqual(chock_policy.table.Decision.deny, wiring.seam.?.decisionFor("device.usb.1d50.6018"));
    try std.testing.expect(!wiring.seam.?.seam().permitted("device.usb.1d50.6018"));
}

test "the device.exposed event records what was actually enforced, not what was asked for" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const table = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "device.usb.1d50.6018", .tool = "device", .decision = .allow },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, table);

    const declared: []const chock_core.devices.Settings = &.{
        .{ .action = "device.usb.1d50.6018" },
        .{ .action = "device.tty.serial.DF62585783282137" },
    };
    const wiring = try devicesFor(arena, gpa, std.testing.io, table, &.{}, "main", "a-model", declared);
    defer if (wiring.host) |host| host.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/01JQ.jsonl", .{buffer[0..len]}, 0);
    const log = try chock_proto.log.Log.open(std.testing.io, log_path, "01JQ");
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(std.testing.io);

    var said: tty.Capture = undefined;
    said.start(std.testing.io, gpa);
    defer said.stop(std.testing.io);

    try recordDevices(gpa, std.testing.io, store, "01JQATTEMPT", wiring.seam);

    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, log_path, arena, .limited(1 << 20));
    try std.testing.expect(std.mem.indexOf(u8, text, "device.exposed") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"action\":\"device.usb.1d50.6018\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"action\":\"device.tty.serial.DF62585783282137\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"decision\":\"allow\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"decision\":\"ask\"") != null);

    const enforced_true = std.mem.indexOf(u8, text, "\"enforced\":true") != null;
    try std.testing.expectEqual(sandbox.expresses.device_passthrough, enforced_true);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"enforced\":false") != null);
}

test "a promise the session made reaches the end of session approval, out of the log" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const allows_the_apply = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "workspace.apply", .decision = .allow },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, allows_the_apply);

    var backing = try chock_proto.storage.Memory.init(gpa, "01PROMISE");
    const storage = backing.storage();
    defer storage.close(io);
    {
        var writing = try storage.lock(io);
        _ = try writing.append(gpa, io, .{ .policy_self = .{ .restrictions = &.{.{
            .action = "workspace.apply",
            .ceiling = .deny,
            .reason = "the user asked me to read this project and change nothing",
        }} } }, 1);
        _ = try writing.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 2);
        try writing.unlock(io);
    }

    var session = chock_proto.state.Session.init(gpa);
    defer session.deinit();
    foldSession(gpa, io, storage, &session);
    try std.testing.expectEqual(@as(usize, 1), session.self_policy.restrictions.items.len);

    const promised = try chock_core.self_policy.restrictionsFrom(
        arena,
        session.self_policy.restrictions.items,
    );

    var locked = try storage.lock(io);
    defer locked.unlock(io) catch {};
    const broker = chock_broker.Broker{
        .policy = allows_the_apply,
        .waiter = chock_broker.Broker.SystemWaiter.waiter(),
    };
    const ask = chock_broker.Broker.Request{
        .action = "workspace.apply",
        .summary = "move 3 objects and the ref refs/chock/01PROMISE",
        .detail = "a1b2c3 the change\n",
        .reason = "the session made a commit",
        .agent_kind = "main",
        .model_alias = "main",
        .tool = "request_action",
        .tool_call_id = "",
        .timeout_ms = 0,
        .self_policy = promised,
    };

    const outcome = try broker.request(gpa, io, storage, &locked, ask, null);
    try std.testing.expectEqual(chock_broker.Broker.Outcome.denied_by_policy, outcome);
    try std.testing.expect(!outcome.permits());

    var without = ask;
    without.self_policy = &.{};
    try std.testing.expectEqual(
        chock_broker.Broker.Outcome.allowed_by_policy,
        try broker.request(gpa, io, storage, &locked, without, null),
    );
}

const GateWaiter = struct {
    gpa: std.mem.Allocator,
    store: chock_proto.storage.Storage,
    locked: *chock_core.arbiter.Locked,
    now_ms: i64 = 1_700_000_000_000,
    waits: usize = 0,
    answered: bool = false,

    fn waiter(self: *GateWaiter) chock_broker.Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_broker.Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = io;
        const self: *GateWaiter = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) chock_broker.Broker.Waiter.Wake {
        const self: *GateWaiter = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        if (!self.answered) {
            self.answered = true;
            if (chock_broker.Broker.openRequest(self.gpa, io, self.store) catch null) |id| {
                if (gateRequestAction(self.gpa, io, self.store, id) catch null) |owned| {
                    defer self.gpa.free(owned);
                    _ = self.locked.append(self.gpa, io, .{ .approval_response = .{
                        .request_id = id,
                        .decision = .approved_by_user_for_session,
                        .responder = "tester",
                        .action = owned,
                    } }, self.now_ms) catch {};
                }
            }
        }
        self.now_ms += @intCast(budget_ms);
        return .slept;
    }
};

fn gateRequestAction(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    id: u64,
) !?[]u8 {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.id != id) continue;
        if (parsed.value.event != .approval_request) continue;
        return try gpa.dupe(u8, parsed.value.event.approval_request.action);
    }
    return null;
}

fn gateCountApprovalRequests(gpa: std.mem.Allocator, io: std.Io, storage: chock_proto.storage.Storage) !usize {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var count: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event == .approval_request) count += 1;
    }
    return count;
}

fn gateGrantServedResponses(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
) ![]chock_proto.event.ApprovalResponse {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var found: std.ArrayList(chock_proto.event.ApprovalResponse) = .empty;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_response) continue;
        const response = parsed.value.event.approval_response;
        if (response.request_id != 0) continue;
        try found.append(gpa, .{
            .request_id = response.request_id,
            .decision = response.decision,
            .responder = try gpa.dupe(u8, response.responder),
            .action = try gpa.dupe(u8, response.action),
            .tool_call_id = try gpa.dupe(u8, response.tool_call_id),
        });
    }
    return found.toOwnedSlice(gpa);
}

fn freeGrantServedResponses(gpa: std.mem.Allocator, responses: []chock_proto.event.ApprovalResponse) void {
    for (responses) |one| {
        gpa.free(one.responder);
        gpa.free(one.action);
        gpa.free(one.tool_call_id);
    }
    gpa.free(responses);
}

test "the loop's own tool gate remembers a for-session grant across separate questions" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    const ask_the_push = try chock_policy.table.Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "git.push", .decision = .ask },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(gpa, ask_the_push);

    var backing = try chock_proto.storage.Memory.init(gpa, "01GATE");
    const storage = backing.storage();
    defer storage.close(io);

    const ask = chock_broker.Broker.Request{
        .action = "git.push",
        .summary = "push the branch to origin",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the task asked for the change to be published",
        .agent_kind = "main",
        .model_alias = "main",
        .tool = "git",
        .tool_call_id = "call1",
    };

    try std.testing.expectEqual(@as(usize, 0), try gateCountApprovalRequests(gpa, io, storage));

    {
        var session = chock_proto.state.Session.init(gpa);
        defer session.deinit();
        foldSession(gpa, io, storage, &session);

        var locked = try storage.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = GateWaiter{ .gpa = gpa, .store = storage, .locked = &locked };
        const broker = chock_broker.Broker{
            .policy = ask_the_push,
            .waiter = waiter.waiter(),
            .grants = .{ .memory = &session.grants, .allocator = session.arena.allocator() },
        };

        const outcome = try broker.request(session.arena.allocator(), io, storage, &locked, ask, null);
        try std.testing.expectEqual(chock_broker.Broker.Outcome.approved_by_user, outcome);
        try std.testing.expectEqual(@as(usize, 1), waiter.waits);
    }
    try std.testing.expectEqual(@as(usize, 1), try gateCountApprovalRequests(gpa, io, storage));
    {
        const served = try gateGrantServedResponses(gpa, io, storage);
        defer freeGrantServedResponses(gpa, served);
        try std.testing.expectEqual(@as(usize, 0), served.len);
    }

    {
        var session = chock_proto.state.Session.init(gpa);
        defer session.deinit();
        foldSession(gpa, io, storage, &session);

        var locked = try storage.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = GateWaiter{ .gpa = gpa, .store = storage, .locked = &locked };
        const broker = chock_broker.Broker{
            .policy = ask_the_push,
            .waiter = waiter.waiter(),
            .grants = .{ .memory = &session.grants, .allocator = session.arena.allocator() },
        };

        const outcome = try broker.request(session.arena.allocator(), io, storage, &locked, ask, null);
        try std.testing.expectEqual(chock_broker.Broker.Outcome.approved_by_user, outcome);
        try std.testing.expectEqual(@as(usize, 0), waiter.waits);
    }
    try std.testing.expectEqual(@as(usize, 1), try gateCountApprovalRequests(gpa, io, storage));
    {
        const served = try gateGrantServedResponses(gpa, io, storage);
        defer freeGrantServedResponses(gpa, served);
        try std.testing.expectEqual(@as(usize, 1), served.len);
        try std.testing.expectEqual(
            chock_proto.event.ApprovalDecision.approved_by_user_for_session,
            served[0].decision,
        );
        try std.testing.expectEqualStrings("git.push", served[0].action);
        try std.testing.expectEqualStrings("call1", served[0].tool_call_id);
        try std.testing.expectEqualStrings("", served[0].responder);
    }
}

test "foldSessionSince, resumed across many calls, reaches the same state a single fold would" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01RESUME");
    const storage = backing.storage();
    defer storage.close(io);

    var resumed = chock_proto.state.Session.init(gpa);
    defer resumed.deinit();
    var at: u64 = 0;
    var round: usize = 0;
    while (round < 3) : (round += 1) {
        var locked = try storage.lock(io);
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            _ = try locked.append(gpa, io, .{ .usage = .{ .input_tokens = round * 10 + i } }, 0);
        }
        try locked.unlock(io);
        foldSessionSince(gpa, io, storage, &resumed, &at);
    }

    var whole = chock_proto.state.Session.init(gpa);
    defer whole.deinit();
    foldSession(gpa, io, storage, &whole);

    try std.testing.expectEqual(whole.last_input_tokens, resumed.last_input_tokens);
    try std.testing.expectEqual(whole.spend.turns, resumed.spend.turns);
    try std.testing.expectEqual(whole.spend.input_tokens, resumed.spend.input_tokens);
}

test "a PolicyFold, resumed the piecemeal way SessionArbiter and ToolNetwork keep one, agrees with a full Session fold on everything either caller reads" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01POLICYFOLD");
    const storage = backing.storage();
    defer storage.close(io);

    const grant_action = "net.connect:build-host";

    var resumed = chock_proto.state.PolicyFold.init(gpa);
    defer resumed.deinit();
    var at: u64 = 0;

    var round: usize = 0;
    while (round < 3) : (round += 1) {
        var locked = try storage.lock(io);
        _ = try locked.append(gpa, io, .{ .message = .{
            .role = .user,
            .content = &.{.{ .text = "round text" }},
        } }, 0);
        if (round == 0) {
            const request_id = try locked.append(gpa, io, .{ .approval_request = .{
                .action = grant_action,
                .summary = "reach the build host",
                .detail = "",
                .reason = "",
                .agent_kind = "main",
                .spawn_chain = &.{},
                .timeout_at_ms = 0,
                .tool_call_id = "call1",
            } }, 0);
            _ = try locked.append(gpa, io, .{ .approval_response = .{
                .request_id = request_id,
                .decision = .approved_by_user_for_session,
                .responder = "person",
                .action = grant_action,
                .tool_call_id = "call1",
            } }, 0);
        }
        if (round == 1) {
            _ = try locked.append(gpa, io, .{ .session_spawn = .{
                .child_session = "01CHILD",
                .child_agent_kind = "subagent",
                .reason = "look something up",
                .budget_max_cost = 1.5,
                .budget_currency = "USD",
            } }, 0);
            _ = try locked.append(gpa, io, .{ .usage = .{
                .input_tokens = 500,
                .output_tokens = 100,
                .cost = .{ .known = .{ .value = 0.02, .currency = "USD" } },
            } }, 0);
        }
        if (round == 2) {
            _ = try locked.append(gpa, io, .{ .policy_self = .{
                .restrictions = &.{.{ .action = grant_action, .ceiling = .deny, .reason = "narrowed mid session" }},
                .authorised = false,
            } }, 0);
        }
        try locked.unlock(io);

        foldSessionSince(gpa, io, storage, &resumed, &at);
    }

    var whole = chock_proto.state.Session.init(gpa);
    defer whole.deinit();
    foldSession(gpa, io, storage, &whole);

    try std.testing.expectEqual(
        whole.self_policy.restrictions.items.len,
        resumed.self_policy.restrictions.items.len,
    );
    try std.testing.expectEqualStrings(
        whole.self_policy.restrictions.items[0].action,
        resumed.self_policy.restrictions.items[0].action,
    );
    try std.testing.expectEqual(whole.children.items.len, resumed.children.items.len);
    try std.testing.expectEqualStrings(whole.children.items[0].session, resumed.children.items[0].session);
    try std.testing.expectEqual(whole.spend.turns, resumed.spend.turns);
    try std.testing.expectEqual(whole.spend.input_tokens, resumed.spend.input_tokens);
    try std.testing.expect(whole.grants.get(grant_action, true) == null);
    try std.testing.expect(resumed.grants.get(grant_action, true) == null);

    try std.testing.expectEqual(@as(usize, 3), whole.context.items.len);
}

test "a mid session restrict_self invalidates a remembered grant on the very next question, and a cache that never refolds does not see it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01NARROW");
    const storage = backing.storage();
    defer storage.close(io);

    const action = "git.push";

    var locked = try storage.lock(io);
    const request_id = try locked.append(gpa, io, .{ .approval_request = .{
        .action = action,
        .summary = "push the branch to origin",
        .detail = "",
        .reason = "",
        .agent_kind = "main",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 0);
    _ = try locked.append(gpa, io, .{ .approval_response = .{
        .request_id = request_id,
        .decision = .approved_by_user_for_session,
        .responder = "person",
        .action = action,
        .tool_call_id = "call1",
    } }, 0);
    try locked.unlock(io);

    var stale = chock_proto.state.Session.init(gpa);
    defer stale.deinit();
    var stale_at: u64 = 0;
    foldSessionSince(gpa, io, storage, &stale, &stale_at);
    try std.testing.expect(stale.grants.get(action, true) != null);

    var live = chock_proto.state.Session.init(gpa);
    defer live.deinit();
    var live_at: u64 = 0;
    foldSessionSince(gpa, io, storage, &live, &live_at);
    try std.testing.expect(live.grants.get(action, true) != null);

    var locked2 = try storage.lock(io);
    _ = try locked2.append(gpa, io, .{ .policy_self = .{
        .restrictions = &.{.{ .action = action, .ceiling = .deny, .reason = "narrowed mid session" }},
        .authorised = false,
    } }, 0);
    try locked2.unlock(io);

    try std.testing.expect(stale.grants.get(action, true) != null);

    foldSessionSince(gpa, io, storage, &live, &live_at);
    try std.testing.expect(live.grants.get(action, true) == null);
}

test "a promise a parent made binds its subagents, out of the parent's own log" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = dir_buffer[0..try tmp.dir.realPath(io, &dir_buffer)];

    const grandparent = "01JQ" ++ "A" ** 22;
    const parent = "01JQ" ++ "B" ** 22;

    const Writer = struct {
        fn write(
            allocator: std.mem.Allocator,
            inner_io: std.Io,
            at: []const u8,
            id: []const u8,
            parent_id: []const u8,
            events: []const chock_proto.event.Event,
        ) !void {
            const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.jsonl", .{ at, id }, 0);
            defer allocator.free(path);
            const log = try chock_proto.log.Log.open(inner_io, path, id);
            var backing = chock_proto.storage.JsonLines{ .log = log };
            const store = backing.storage();
            defer store.close(inner_io);
            var locked = try store.lock(inner_io);
            _ = try locked.append(allocator, inner_io, .{ .session_start = .{
                .agent_kind = "main",
                .model_alias = "main",
                .parent_session = parent_id,
            } }, 1);
            for (events, 2..) |one, time| {
                _ = try locked.append(allocator, inner_io, one, @intCast(time));
            }
            try locked.unlock(inner_io);
        }
    };

    try Writer.write(gpa, io, dir, grandparent, "", &.{
        .{ .policy_self = .{ .restrictions = &.{.{
            .action = "workspace.apply",
            .ceiling = .deny,
            .reason = "the user asked for a read only review",
        }} } },
    });
    try Writer.write(gpa, io, dir, parent, grandparent, &.{
        .{ .policy_self = .{ .restrictions = &.{.{
            .action = "net.fetch",
            .ceiling = .ask,
            .reason = "no network without a person",
        }} } },
    });

    var child = chock_proto.state.Session.init(gpa);
    defer child.deinit();
    try child.apply(.{ .id = 1, .session = "01CHILD", .time_ms = 1, .event = .{ .policy_self = .{
        .restrictions = &.{.{
            .action = "git.push",
            .ceiling = .deny,
            .reason = "nothing leaves this machine",
        }},
    } } });

    const promised = try promisesFor(gpa, arena, io, dir, parent, &child);
    try std.testing.expectEqual(@as(usize, 3), promised.len);

    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.ratchet.ceilingFor(promised, "workspace.apply"),
    );
    try std.testing.expectEqual(
        chock_policy.table.Decision.ask,
        chock_policy.ratchet.ceilingFor(promised, "net.fetch"),
    );
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.ratchet.ceilingFor(promised, "git.push"),
    );
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.ratchet.ceilingFor(promised, "nix.build"),
    );

    const alone = try promisesFor(gpa, arena, io, dir, "", &child);
    try std.testing.expectEqual(@as(usize, 1), alone.len);
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.ratchet.ceilingFor(alone, "workspace.apply"),
    );

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    const gone = "01JQ" ++ "Z" ** 22;
    const missing = try promisesFor(gpa, arena, io, dir, gone, &child);
    try std.testing.expectEqual(@as(usize, 1), missing.len);
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.ratchet.ceilingFor(missing, "git.push"),
    );
    try std.testing.expect(std.mem.indexOf(u8, said.err(), gone) != null);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "may not be applied") != null);

    said.clear();
    const bad = try promisesFor(gpa, arena, io, dir, "../../etc", &child);
    try std.testing.expectEqual(@as(usize, 1), bad.len);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "not a session identifier") != null);
    try std.testing.expectEqualStrings("", said.out());
}

const tree_child_path = @import("tree_child_path").tree_child_path;

test "a promise a grandparent made binds a grandchild of a tree that really ran" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_dir = dir_buffer[0..try tmp.dir.realPath(io, &dir_buffer)];
    try tmp.dir.createDir(io, "project", .default_dir);
    try tmp.dir.createDir(io, "sessions", .default_dir);

    const project = try std.fmt.allocPrint(arena, "{s}/project", .{root_dir});
    const dir = try std.fmt.allocPrint(arena, "{s}/sessions", .{root_dir});

    const root_session = "01JQ" ++ "A" ** 22;
    try runTreeAgent(arena, io, project, dir, root_session,
        \\promise workspace.apply deny the user asked for a read only review
        \\spawn coder
        \\> promise net.fetch ask no network without a person
        \\> spawn worker
        \\> > promise git.push deny nothing leaves this machine
        \\> > say I read the parser
    );

    var top = chock_proto.state.Session.init(gpa);
    defer top.deinit();
    try std.testing.expect(foldSessionById(gpa, io, dir, root_session, &top));
    try std.testing.expectEqual(@as(usize, 1), top.children.items.len);

    var middle = chock_proto.state.Session.init(gpa);
    defer middle.deinit();
    const middle_id = try arena.dupe(u8, top.children.items[0].session);
    try std.testing.expect(foldSessionById(gpa, io, dir, middle_id, &middle));
    try std.testing.expectEqual(@as(usize, 1), middle.children.items.len);

    var bottom = chock_proto.state.Session.init(gpa);
    defer bottom.deinit();
    const bottom_id = try arena.dupe(u8, middle.children.items[0].session);
    try std.testing.expect(foldSessionById(gpa, io, dir, bottom_id, &bottom));
    try std.testing.expect(session_paths.isValidId(middle_id));
    try std.testing.expect(session_paths.isValidId(bottom_id));
    try std.testing.expectEqualStrings(middle_id, bottom.parent_session);

    const promised = try promisesFor(gpa, arena, io, dir, bottom.parent_session, &bottom);
    try std.testing.expectEqual(@as(usize, 3), promised.len);
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.ratchet.ceilingFor(promised, "workspace.apply"),
    );
    try std.testing.expectEqual(
        chock_policy.table.Decision.ask,
        chock_policy.ratchet.ceilingFor(promised, "net.fetch"),
    );
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.ratchet.ceilingFor(promised, "git.push"),
    );
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.ratchet.ceilingFor(promised, "nix.build"),
    );

    const at_the_middle = try promisesFor(gpa, arena, io, dir, middle.parent_session, &middle);
    try std.testing.expectEqual(@as(usize, 2), at_the_middle.len);
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.ratchet.ceilingFor(at_the_middle, "git.push"),
    );
    const alone = try promisesFor(gpa, arena, io, dir, "", &bottom);
    try std.testing.expectEqual(@as(usize, 1), alone.len);
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.ratchet.ceilingFor(alone, "workspace.apply"),
    );
}

fn runTreeAgent(
    arena: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    dir: []const u8,
    session: []const u8,
    task: []const u8,
) !void {
    const prepared = chock_core.subagent.Prepared{
        .child_session = try arena.dupe(u8, session),
        .log_path = try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ dir, session }),
        .scratchpad_path = try arena.dupe(u8, ""),
    };
    const argv = try chock_core.subagent.commandLine(arena, .{
        .exe_path = tree_child_path,
        .project_root = project,
        .parent_session = "",
    }, .{
        .agent_kind = "main",
        .task = task,
        .reason = chock_core.subagent.reasonFor(task),
    }, prepared);

    var env = try std.testing.environ.createMap(arena);
    defer env.deinit();
    try env.put("CHOCK_TEST_SESSION_DIR", dir);

    var child = try std.process.spawn(io, .{
        .argv = argv,
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    _ = child.wait(io) catch {};
}

test "a review that this session cannot pay for or start is refused, never skipped" {
    const cap = chock_cost.budget.Budget{ .max_cost = 5.0, .currency = "USD" };
    const limits = chock_policy.subagents.Limits{ .max_depth = 3, .max_width = 2 };
    const fresh = chock_proto.state.Spend{ .amount = 1.0, .currency = "USD", .turns = 3 };
    const first = chock_policy.subagents.Standing{ .depth = 1, .width = 0 };

    {
        const bounds = reviewBounds(limits, first, cap, fresh, &.{});
        try std.testing.expectEqual(@as(?chock_policy.subagents.Refusal, null), bounds.refused_by_limits);
        try std.testing.expect(!bounds.nothing_left);
        try std.testing.expectEqual(@as(f64, 4.0), bounds.budget.?.max_cost);
        try std.testing.expectEqualStrings("USD", bounds.budget.?.currency);
    }

    {
        const gone = chock_proto.state.Spend{ .amount = 5.5, .currency = "USD", .turns = 9 };
        const bounds = reviewBounds(limits, first, cap, gone, &.{});
        try std.testing.expectEqual(@as(?chock_cost.budget.Budget, null), bounds.budget);
        try std.testing.expect(bounds.nothing_left);
    }

    {
        const promised = [_]chock_proto.state.Child{
            .{ .session = "01A", .agent_kind = "worker", .reason = "one", .budget_max_cost = 4.0, .budget_currency = "USD" },
        };
        const bounds = reviewBounds(limits, first, cap, fresh, &promised);
        try std.testing.expectEqual(@as(?chock_cost.budget.Budget, null), bounds.budget);
        try std.testing.expect(bounds.nothing_left);
    }

    {
        const deep = chock_policy.subagents.Standing{ .depth = 3, .width = 0 };
        const bounds = reviewBounds(limits, deep, cap, fresh, &.{});
        try std.testing.expectEqual(chock_policy.subagents.Refusal.depth, bounds.refused_by_limits.?);
    }

    {
        const none_allowed = chock_policy.subagents.Limits{ .max_depth = 6, .max_width = 0 };
        const bounds = reviewBounds(none_allowed, first, cap, fresh, &.{});
        try std.testing.expectEqual(chock_policy.subagents.Refusal.width, bounds.refused_by_limits.?);
    }

    {
        const bounds = reviewBounds(limits, first, null, fresh, &.{});
        try std.testing.expectEqual(@as(?chock_cost.budget.Budget, null), bounds.budget);
        try std.testing.expect(!bounds.nothing_left);
        try std.testing.expectEqual(@as(?chock_policy.subagents.Refusal, null), bounds.refused_by_limits);
    }
}

test "the reviewer this run wires in is the kind the policy table names, and it gets no scratchpad" {
    var child = reviewChild(std.testing.allocator, .empty, undefined, undefined, .{});
    var spawner = ReviewSpawner{
        .child = child.spawner(),
        .budget = null,
        .nothing_left = false,
        .refused_by_limits = null,
    };
    try std.testing.expectEqualStrings(
        chock_broker.review.default_kind,
        spawner.reviewer().kind,
    );
    try std.testing.expect(child.no_scratchpad);
}

const FakeReviewChild = struct {
    prepared: usize = 0,
    ran: usize = 0,
    outcome: chock_proto.event.AgentOutcome = .finished,
    answer: []const u8 = "{\"verdict\":\"approve\",\"why\":\"the diff is the fix the task asked for\"}",

    fn spawner(self: *FakeReviewChild) chock_core.subagent.Spawner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.subagent.Spawner.VTable{ .prepare = prepareFn, .run = runFn };

    fn prepareFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: chock_core.subagent.Request,
    ) chock_core.subagent.Error!chock_core.subagent.Prepared {
        _ = io;
        _ = request;
        const self: *FakeReviewChild = @ptrCast(@alignCast(ptr));
        self.prepared += 1;
        return .{
            .child_session = try allocator.dupe(u8, "01REVIEWCHILD"),
            .log_path = try allocator.dupe(u8, "/tmp/chock/01REVIEWCHILD/log.jsonl"),
            .scratchpad_path = try allocator.dupe(u8, ""),
        };
    }

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: chock_core.subagent.Request,
        prepared: chock_core.subagent.Prepared,
    ) chock_core.subagent.Error!chock_core.subagent.Report {
        _ = io;
        _ = request;
        _ = prepared;
        const self: *FakeReviewChild = @ptrCast(@alignCast(ptr));
        self.ran += 1;
        return .{ .outcome = self.outcome, .result = try allocator.dupe(u8, self.answer) };
    }
};

const a_case = chock_broker.review.Case{
    .action = "workspace.apply",
    .summary = "move 3 objects and one ref",
    .detail = "a1b2c3 fix the parser\n",
    .reason = "the session made a commit",
    .chain = &.{ "main", "coder" },
    .decision = .agent_review,
};

test "a reviewer is a child in its parent's log, so the width bound can see it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01PARENT");
    const storage = backing.storage();
    defer storage.close(io);

    var locked = try storage.lock(io);

    var child = FakeReviewChild{};
    var spawner = ReviewSpawner{
        .child = child.spawner(),
        .budget = .{ .max_cost = 4.0, .currency = "USD" },
        .nothing_left = false,
        .refused_by_limits = null,
        .locked = &locked,
    };

    const report = try spawner.reviewer().review(gpa, io, a_case);
    defer chock_broker.review.freeReport(gpa, report);
    try std.testing.expectEqual(@as(usize, 1), child.ran);
    try std.testing.expectEqual(chock_broker.review.Verdict.approved, report.verdict);

    try locked.unlock(io);

    var session = chock_proto.state.Session.init(gpa);
    defer session.deinit();
    var spawn_events: usize = 0;
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
        if (parsed.value.event == .session_spawn) spawn_events += 1;
    }

    try std.testing.expectEqual(@as(usize, 1), spawn_events);
    try std.testing.expectEqual(@as(usize, 1), session.children.items.len);
    try std.testing.expectEqualStrings(
        chock_broker.review.default_kind,
        session.children.items[0].agent_kind,
    );
    try std.testing.expectEqualStrings("01REVIEWCHILD", session.children.items[0].session);
    try std.testing.expectEqual(@as(f64, 4.0), session.children.items[0].budget_max_cost);

    const one_child = chock_policy.subagents.Limits{ .max_depth = 6, .max_width = 1 };
    const standing = chock_policy.subagents.Standing{
        .depth = 1,
        .width = session.children.items.len,
    };
    const after = reviewBounds(one_child, standing, null, session.spend, session.children.items);
    try std.testing.expectEqual(chock_policy.subagents.Refusal.width, after.refused_by_limits.?);

    const before = reviewBounds(one_child, .{ .depth = 1, .width = 0 }, null, session.spend, &.{});
    try std.testing.expectEqual(@as(?chock_policy.subagents.Refusal, null), before.refused_by_limits);
}

test "a reviewer nothing can record does not run, and that is a refusal" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var child = FakeReviewChild{};
    var spawner = ReviewSpawner{
        .child = child.spawner(),
        .budget = null,
        .nothing_left = false,
        .refused_by_limits = null,
        .locked = null,
    };

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    try std.testing.expectError(
        error.ReviewNotRun,
        spawner.reviewer().review(gpa, io, a_case),
    );
    try std.testing.expectEqual(@as(usize, 1), child.prepared);
    try std.testing.expectEqual(@as(usize, 0), child.ran);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "no reviewer was started") != null);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), a_case.action) != null);
    try std.testing.expectEqualStrings("", said.out());
}

test "a reviewer child reads its own command line and holds no tools because of what it reads" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = try chock_core.subagent.commandLine(arena, .{
        .exe_path = "/nix/store/aaa-chock/bin/chock",
        .project_root = "/home/someone/project",
        .parent_session = "01PARENT",
        .parent_chain = &.{.{ .agent_kind = "main", .reason = "workspace.apply" }},
    }, .{
        .agent_kind = chock_broker.review.default_kind,
        .task = "a case to weigh",
        .shape = .{ .schema = &chock_broker.review.result_fields },
        .reason = "workspace.apply",
    }, .{
        .child_session = try arena.dupe(u8, "01REVIEWER"),
        .log_path = try arena.dupe(u8, "/tmp/chock/01REVIEWER/log.jsonl"),
        .scratchpad_path = try arena.dupe(u8, ""),
    });

    const options = try parseOptions(arena, argv[2..]);
    try std.testing.expectEqualStrings(chock_broker.review.default_kind, options.agent_kind);
    try std.testing.expectEqual(chock_core.tools.Role.arbitrator, agentRole(options));

    const support = chock_core.tools.Support{
        .adapter = .openai_compatible,
        .memory = true,
        .provisioning = true,
        .role = agentRole(options),
    };
    const definitions = try chock_core.tools.Registry.definitions(arena, support);
    try std.testing.expectEqual(@as(usize, 0), definitions.len);
    const prompt = try chock_core.prompt.build(arena, .{}, definitions, .{});
    try std.testing.expect(std.mem.indexOf(u8, prompt, "you have no tools") != null);

    const worker_argv = try chock_core.subagent.commandLine(arena, .{
        .exe_path = "/nix/store/aaa-chock/bin/chock",
        .project_root = "/home/someone/project",
        .parent_session = "01PARENT",
        .parent_chain = &.{.{ .agent_kind = "main", .reason = "do a piece of the work" }},
    }, .{
        .agent_kind = "worker",
        .task = "a piece of the work",
        .shape = .prose,
        .reason = "do a piece of the work",
    }, .{
        .child_session = try arena.dupe(u8, "01WORKER"),
        .log_path = try arena.dupe(u8, "/tmp/chock/01WORKER/log.jsonl"),
        .scratchpad_path = try arena.dupe(u8, "/tmp/chock/01PARENT/agents/01WORKER/scratch"),
    });
    const worker = try parseOptions(arena, worker_argv[2..]);
    try std.testing.expectEqual(chock_core.tools.Role.worker, agentRole(worker));
    const worker_definitions = try chock_core.tools.Registry.definitions(arena, .{
        .adapter = .openai_compatible,
        .role = agentRole(worker),
    });
    try std.testing.expect(worker_definitions.len > 0);
}

test "the end of session approval waits for a person, and agent_then_human can therefore run" {
    try std.testing.expect(approval.timeoutMs(true) > 0);
    try std.testing.expectEqual(chock_broker.Broker.default_timeout_ms, approval.timeoutMs(true));

    try std.testing.expectEqual(@as(i64, 0), approval.timeoutMs(false));
}

test "a session with a display asks in it, and never at the prompt as well" {
    try std.testing.expectEqual(.display, asksHere(true, true));
    try std.testing.expectEqual(.display, asksHere(true, false));
    try std.testing.expectEqual(.terminal, asksHere(false, true));
    try std.testing.expectEqual(.nobody, asksHere(false, false));

    try std.testing.expect(chock_broker.socket.timeoutMs(true, 0) > 0);
    try std.testing.expectEqual(@as(i64, 0), chock_broker.socket.timeoutMs(false, 0));
}

test "the header names every sandbox layer the driver gives, and says the word off for one it does not" {
    const every = sandbox.Sandbox.Guarantees.initFull();
    const all_seen = LayerWitness{ .probed = every };
    const on = sandboxLayers(every, all_seen, .none, "worktree");
    try std.testing.expectEqual(@as(usize, 6), on.len);
    for (on) |one| try std.testing.expectEqual(ui.Layer.State.on, one.state);
    try std.testing.expectEqualStrings("net", on[0].name);
    try std.testing.expectEqualStrings("none", on[0].note);
    try std.testing.expectEqualStrings("fs", on[1].name);
    try std.testing.expectEqualStrings("worktree", on[1].note);

    const none = sandboxLayers(sandbox.Sandbox.Guarantees.initEmpty(), all_seen, .none, "worktree");
    for (none) |one| {
        try std.testing.expectEqual(ui.Layer.State.unsupported, one.state);
        try std.testing.expect(one.state.word().len != 0);
    }

    var short = every;
    short.remove(.path_restricted);
    const missing = sandboxLayers(short, all_seen, .none, "worktree");
    for (missing) |one| {
        if (std.mem.eql(u8, one.name, "landlock")) {
            try std.testing.expectEqual(ui.Layer.State.unsupported, one.state);
        } else {
            try std.testing.expectEqual(ui.Layer.State.on, one.state);
        }
    }
}

test "a layer the driver gives but this run could not get reads unavailable, not on" {
    const every = sandbox.Sandbox.Guarantees.initFull();
    var landlock_only = sandbox.Sandbox.Guarantees.initEmpty();
    landlock_only.insert(.path_restricted);

    const blocked = sandboxLayers(every, .{ .probed = every, .unavailable = landlock_only }, .none, "worktree");
    for (blocked) |one| {
        if (std.mem.eql(u8, one.name, "landlock")) {
            try std.testing.expectEqual(ui.Layer.State.unavailable, one.state);
            try std.testing.expectEqualStrings("BLOCKED", one.state.word());
        } else {
            try std.testing.expectEqual(ui.Layer.State.on, one.state);
        }
    }

    var short = every;
    short.remove(.path_restricted);
    const never_had = sandboxLayers(short, .{ .probed = every, .unavailable = landlock_only }, .none, "worktree");
    for (never_had) |one| {
        if (std.mem.eql(u8, one.name, "landlock")) {
            try std.testing.expectEqual(ui.Layer.State.unsupported, one.state);
        }
    }
}

test "a layer nothing probed still reads on, because the driver dies rather than run without it" {
    // Every step of `applyLayers` in `lib/chock-sandbox/linux/driver.zig` ends in
    // `die`, so no layer can quietly fail to apply and still let the tool call
    // run. A tick means the layer is enforced, or the call dies.
    const every = sandbox.Sandbox.Guarantees.initFull();
    const unprobed = sandboxLayers(every, .{}, .none, "worktree");
    for (unprobed) |one| try std.testing.expectEqual(ui.Layer.State.on, one.state);

    var landlock_only = sandbox.Sandbox.Guarantees.initEmpty();
    landlock_only.insert(.path_restricted);
    const refused = sandboxLayers(
        every,
        .{ .probed = landlock_only, .unavailable = landlock_only },
        .none,
        "worktree",
    );
    for (refused) |one| {
        if (std.mem.eql(u8, one.name, "landlock")) {
            try std.testing.expectEqual(ui.Layer.State.unavailable, one.state);
        } else {
            try std.testing.expectEqual(ui.Layer.State.on, one.state);
        }
    }
}

test "the header of a normal linux session is six ticks and no other mark" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const layers = sandboxLayers(sandbox.Sandbox.Guarantees.initFull(), .{}, .none, "worktree");
    var said: std.ArrayList(u8) = .empty;
    for (layers) |one| {
        if (said.items.len != 0) try said.appendSlice(arena, "  ");
        try said.appendSlice(arena, try ui.layerText(arena, one, false));
    }
    try std.testing.expectEqualStrings(
        "\u{2713} net none  \u{2713} fs worktree  \u{2713} pid  " ++
            "\u{2713} ipc  \u{2713} seccomp  \u{2713} landlock",
        said.items,
    );
}

test "a layer this platform never applies is drawn as missing and never as on" {
    // Darwin's driver declares four guarantees, the network, the signals, the IPC
    // and the paths, and declares neither a system call filter nor a mounted
    // workspace.
    const darwin = sandbox.Sandbox.Guarantees.initMany(&.{
        .network_isolated,
        .signal_isolated,
        .ipc_isolated,
        .path_restricted,
    });
    const built = sandboxLayers(darwin, .{}, .none, "worktree");
    for (built) |one| {
        const never = std.mem.eql(u8, one.name, "fs") or std.mem.eql(u8, one.name, "seccomp");
        if (never) {
            try std.testing.expectEqual(ui.Layer.State.unsupported, one.state);
            try std.testing.expectEqualStrings("NONE", one.state.word());
        } else {
            try std.testing.expectEqual(ui.Layer.State.on, one.state);
        }
    }
}

test "this machine really answers for the layers the witness claims to measure" {
    // A kernel that refuses Landlock is a real machine, so this asserts the shape
    // and not the verdict.
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    const given = sandbox.Sandbox.guarantees;
    const seen = witnessLayers(std.testing.allocator, given);

    var stray = seen.unavailable;
    stray = stray.differenceWith(seen.probed);
    try std.testing.expectEqual(@as(usize, 0), stray.count());

    var uninvited = seen.probed;
    uninvited = uninvited.differenceWith(given);
    try std.testing.expectEqual(@as(usize, 0), uninvited.count());

    for ([_]sandbox.Sandbox.Guarantee{
        .path_restricted,
        .syscall_restricted,
        .signal_isolated,
        .ipc_isolated,
        .network_isolated,
    }) |guarantee| {
        try std.testing.expect(seen.probed.contains(guarantee));
    }

    try std.testing.expect(!seen.probed.contains(.workspace_mounted));
}

test "a session that gave the network layer up says so, and a filtered one does not" {
    const every = sandbox.Sandbox.Guarantees.initFull();

    const seen = LayerWitness{ .probed = every };
    const filtered = sandboxLayers(every, seen, .filtered, "overlay");
    try std.testing.expectEqual(ui.Layer.State.on, filtered[0].state);
    try std.testing.expectEqualStrings("filtered", filtered[0].note);

    const host = sandboxLayers(every, seen, .host, "overlay");
    try std.testing.expectEqual(ui.Layer.State.off, host[0].state);
    try std.testing.expectEqualStrings("host", host[0].note);
    try std.testing.expectEqualStrings("OFF", host[0].state.word());
    for (host[1..]) |one| try std.testing.expectEqual(ui.Layer.State.on, one.state);

    try std.testing.expectEqualStrings("overlay", host[1].note);
}

test "the word beside the net layer is the name of the mode, for every mode there is" {
    const every = sandbox.Sandbox.Guarantees.initFull();
    for (std.enums.values(sandbox.namespace.Network)) |mode| {
        const built = sandboxLayers(every, .{ .probed = every }, mode, "worktree");
        try std.testing.expectEqualStrings(@tagName(mode), built[0].note);
    }
}

test "a provisioned closure that overlaps the dev shell's is mounted once and not twice" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();

    var context = chock_core.tools.Context{};
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var mounts = SessionMounts{
        .arena = arena_state.allocator(),
        .context = &context,
        .tool_env = &tool_env,
    };
    var provisioning = ProvisionToolRunner{
        .inner = recorder.runner(),
        .settings = null,
        .arena = arena_state.allocator(),
        .host_env = &tool_env,
        .environ = .empty,
        .mounts = &mounts,
    };

    const dev_shell = [_][]const u8{
        "/nix/store/aaa-glibc",
        "/nix/store/bbb-zig",
    };
    try mounts.start(&dev_shell);

    const closure = [_][]const u8{
        "/nix/store/aaa-glibc",
        "/nix/store/ccc-ripgrep",
    };
    try provisioning.adopt("ripgrep", .{
        .program = "ripgrep",
        .installable = "nixpkgs#ripgrep",
        .bin_dirs = &.{},
        .store_paths = &closure,
    });

    try std.testing.expectEqual(@as(usize, 3), context.store_paths.len);
    var glibc: usize = 0;
    for (context.store_paths) |path| {
        if (std.mem.eql(u8, path, "/nix/store/aaa-glibc")) glibc += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), glibc);

    const second = [_][]const u8{ "/nix/store/aaa-glibc", "/nix/store/ddd-fd" };
    try provisioning.adopt("fd", .{
        .program = "fd",
        .installable = "nixpkgs#fd",
        .bin_dirs = &.{},
        .store_paths = &second,
    });
    try std.testing.expectEqual(@as(usize, 4), context.store_paths.len);
}

test "two provisioned programs get two sets of garbage collector roots, and the dev shell releases both" {
    const gpa = std.testing.allocator;

    const first = try providedRootPrefix(gpa, "/state/dev-shell/proj", "ripgrep");
    defer gpa.free(first);
    const second = try providedRootPrefix(gpa, "/state/dev-shell/proj", "fd");
    defer gpa.free(second);
    try std.testing.expect(!std.mem.eql(u8, first, second));

    const leaf = std.fs.path.basename(first);
    try std.testing.expect(std.mem.startsWith(u8, leaf, chock_nix.DevShell.root_link_name));
    try std.testing.expectEqualStrings("gcroot-provided-ripgrep", leaf);
}

test "a session with no MCP server passes every tool call through, byte for byte" {
    const gpa = std.testing.allocator;

    var state = McpState.init(gpa);
    defer state.deinit(std.testing.io);

    for ([_][]const u8{ "run_command", "read_file", "write_file", "get_current_time" }) |name| {
        var inner = CountingToolRunner{};
        var mcp_aware = McpToolRunner{ .inner = inner.runner(), .state = &state };

        const result = try mcp_aware.runner().dispatch(gpa, std.testing.io, .{
            .call_id = "call1",
            .tool = name,
            .arguments = "{\"argv\":[\"git\",\"status\"]}",
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try std.testing.expectEqual(@as(usize, 1), inner.calls);
        try std.testing.expectEqualStrings("the real git ran", result.output);
        try std.testing.expect(!result.is_error);
        try std.testing.expectEqualStrings("{\"argv\":[\"git\",\"status\"]}", inner.last_arguments);
    }
}

test "a call to an MCP tool is answered here and never reaches the runners below" {
    const gpa = std.testing.allocator;

    var host = ProbeHost{ .text = "the server answered", .is_error = false };
    var state = McpState.init(gpa);
    defer state.deinit(std.testing.io);
    var server = chock_core.mcp.Server{ .name = "probe", .host = host.host() };
    state.session.servers = @as(*[1]chock_core.mcp.Server, &server);

    var policy = AllowEverything{};
    try state.session.admit(&server, &.{.{ .name = "probe_tool" }}, policy.decider());

    var log = try PermittingLog.init(gpa);
    defer log.deinit(std.testing.io);
    try log.arm(std.testing.io);
    state.session.asker = log.asker();

    var inner = CountingToolRunner{};
    var mcp_aware = McpToolRunner{ .inner = inner.runner(), .state = &state };

    const result = try mcp_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call7",
        .tool = "probe_tool",
        .arguments = "{}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expectEqual(@as(usize, 0), inner.calls);
    try std.testing.expectEqual(@as(usize, 1), host.calls);
    try std.testing.expectEqualStrings("the server answered", result.output);
    try std.testing.expectEqualStrings("call7", result.call_id);
}

test "one locked handle reaches all four askers, and one that missed it runs nothing" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var server_host = ProbeHost{ .text = "the server answered", .is_error = false };
    var mcp_state = McpState.init(gpa);
    defer mcp_state.deinit(io);
    var server = chock_core.mcp.Server{ .name = "probe", .host = server_host.host() };
    mcp_state.session.servers = @as(*[1]chock_core.mcp.Server, &server);

    var plugin_probe = PluginProbeHost{ .text = "the plugin answered", .is_error = false };
    var plugin_state = PluginState.init(gpa);
    defer plugin_state.deinit(io);

    var policy = AllowEverything{};
    try mcp_state.session.admit(&server, &.{.{ .name = "server_tool" }}, policy.decider());
    _ = try plugin_state.session.admit("hello", .{
        .name = "written by the author",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{.{ .name = "plugin_tool" }},
    }, policy.decider());
    var loaded = [_]chock_core.plugin.Loaded{.{ .name = "hello", .host = plugin_probe.host() }};
    plugin_state.session.plugins = &loaded;

    var log = try PermittingLog.init(gpa);
    defer log.deinit(io);
    try log.arm(io);
    mcp_state.session.asker = .{ .arbiter = log.asker().arbiter };
    plugin_state.session.asker = .{ .arbiter = log.asker().arbiter };

    var inner = CountingToolRunner{};
    var git_aware = GitToolRunner{ .inner = inner.runner(), .asker = .{ .arbiter = log.asker().arbiter } };
    var mcp_aware = McpToolRunner{ .inner = git_aware.runner(), .state = &mcp_state };
    var plugin_aware = PluginToolRunner{ .inner = mcp_aware.runner(), .state = &plugin_state };

    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    var context = chock_core.tools.Context{};
    var mounts = SessionMounts{ .arena = gpa, .context = &context, .tool_env = &tool_env };
    var nix_build = NixBuildToolRunner{
        .inner = inner.runner(),
        .settings = null,
        .arena = gpa,
        .host_env = &tool_env,
        .environ = .empty,
        .mounts = &mounts,
        .asker = .{ .arbiter = log.asker().arbiter },
    };

    for ([_][]const u8{ "server_tool", "plugin_tool" }) |name| {
        const early = try plugin_aware.runner().dispatch(gpa, io, .{
            .call_id = "call1",
            .tool = name,
            .arguments = "{}",
        });
        defer gpa.free(early.call_id);
        defer gpa.free(early.output);
        try std.testing.expect(early.is_error);
        try std.testing.expect(std.mem.indexOf(
            u8,
            early.output,
            chock_core.arbiter.not_asked.outcome,
        ) != null);
    }
    {
        const early = try plugin_aware.runner().dispatch(gpa, io, .{
            .call_id = "call1",
            .tool = "run_command",
            .arguments = "{\"argv\":[\"git\",\"add\",\"-A\"]}",
        });
        defer gpa.free(early.call_id);
        defer gpa.free(early.output);
        try std.testing.expect(early.is_error);
        try std.testing.expect(std.mem.indexOf(
            u8,
            early.output,
            chock_core.arbiter.not_asked.outcome,
        ) != null);
    }
    try std.testing.expectEqual(@as(usize, 0), server_host.calls);
    try std.testing.expectEqual(@as(usize, 0), plugin_probe.calls);
    try std.testing.expectEqual(@as(usize, 0), inner.calls);

    try std.testing.expect(nix_build.asker.?.locked == null);

    giveLockedToAskers(
        &mcp_state.session,
        &plugin_state.session,
        &git_aware,
        &nix_build,
        &log.locked,
    );
    try std.testing.expect(nix_build.asker.?.locked != null);

    const from_server = try plugin_aware.runner().dispatch(gpa, io, .{
        .call_id = "call2",
        .tool = "server_tool",
        .arguments = "{}",
    });
    defer gpa.free(from_server.call_id);
    defer gpa.free(from_server.output);
    try std.testing.expectEqualStrings("the server answered", from_server.output);

    const from_plugin = try plugin_aware.runner().dispatch(gpa, io, .{
        .call_id = "call3",
        .tool = "plugin_tool",
        .arguments = "{}",
    });
    defer gpa.free(from_plugin.call_id);
    defer gpa.free(from_plugin.output);
    try std.testing.expectEqualStrings("the plugin answered", from_plugin.output);

    const from_git = try plugin_aware.runner().dispatch(gpa, io, .{
        .call_id = "call4",
        .tool = "run_command",
        .arguments = "{\"argv\":[\"git\",\"add\",\"-A\"]}",
    });
    defer gpa.free(from_git.call_id);
    defer gpa.free(from_git.output);
    try std.testing.expect(!from_git.is_error);
    try std.testing.expectEqualStrings("the real git ran", from_git.output);

    try std.testing.expectEqual(@as(usize, 1), server_host.calls);
    try std.testing.expectEqual(@as(usize, 1), plugin_probe.calls);
    try std.testing.expectEqual(@as(usize, 1), inner.calls);
}

test "the policy this wiring builds names the action, folds the chain, and refuses a child its parent lacks" {
    const gpa = std.testing.allocator;
    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "mcp.time.*", .decision = .deny },
        \\            .{ .agent_kind = "fetcher", .action = "mcp.time.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const table = try chock_policy.table.Table.parse(gpa, source, null);
    defer chock_policy.table.Table.destroy(gpa, table);

    var action_buffer: [chock_core.mcp.max_action_bytes]u8 = undefined;
    const action = chock_core.mcp.actionInto(&action_buffer, "time", "get_current_time").?;
    try std.testing.expectEqualStrings("mcp.time.tool.get_current_time", action);

    {
        var policy = TablePolicy{
            .policy = table,
            .chain = &.{"fetcher"},
            .agent_kind = "fetcher",
            .model = "m",
        };
        try std.testing.expectEqual(
            chock_policy.table.Decision.allow,
            policy.answer("get_current_time", action),
        );
    }

    {
        var policy = TablePolicy{
            .policy = table,
            .chain = &.{ "main", "fetcher" },
            .agent_kind = "fetcher",
            .model = "m",
        };
        try std.testing.expectEqual(
            chock_policy.table.Decision.deny,
            policy.answer("get_current_time", action),
        );
    }
}

test "a server reaches the network only when a rule says so, and never by default" {
    const gpa = std.testing.allocator;

    var buffer: [chock_core.mcp.max_action_bytes]u8 = undefined;
    const action = chock_core.mcp.networkActionInto(&buffer, "github").?;
    try std.testing.expectEqualStrings("mcp.github.network", action);

    const cases = [_]struct { source: [:0]const u8, filtered: bool }{
        .{ .source = ".{ .policy = .{ .rules = .{} } }", .filtered = false },
        .{
            .source = ".{ .policy = .{ .rules = .{ .{ .action = \"mcp.github.network\", .decision = .ask } } } }",
            .filtered = false,
        },
        .{
            .source = ".{ .policy = .{ .rules = .{ .{ .action = \"mcp.github.network\", .decision = .deny } } } }",
            .filtered = false,
        },
        .{
            .source = ".{ .policy = .{ .rules = .{ .{ .action = \"mcp.github.network\", .decision = .allow } } } }",
            .filtered = true,
        },
        .{
            .source = ".{ .policy = .{ .rules = .{ .{ .action = \"mcp.github.tool.*\", .decision = .allow } } } }",
            .filtered = false,
        },
    };

    for (cases) |one| {
        const table = try chock_policy.table.Table.parse(gpa, one.source, null);
        defer chock_policy.table.Table.destroy(gpa, table);
        var policy = TablePolicy{
            .policy = table,
            .chain = &.{"main"},
            .agent_kind = "main",
            .model = "m",
        };
        const allowed = policy.answer("github", action) == .allow;
        try std.testing.expectEqual(one.filtered, allowed);
    }
}

const ProbeHost = struct {
    text: []const u8,
    is_error: bool,
    calls: usize = 0,

    fn host(self: *ProbeHost) chock_core.mcp.Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.mcp.Host.VTable{ .list = listFn, .call = callFn };

    fn listFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        budget_ns: u64,
    ) chock_core.mcp.Error![]const chock_core.mcp.Declared {
        _ = ptr;
        _ = arena;
        _ = io;
        _ = budget_ns;
        return &.{};
    }

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) chock_core.mcp.Error!chock_core.mcp.Outcome {
        _ = arena;
        _ = io;
        _ = name;
        _ = arguments;
        _ = budget_ns;
        const self: *ProbeHost = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        return .{ .text = self.text, .is_error = self.is_error };
    }
};

test "a session with no plugin passes every tool call through, byte for byte" {
    const gpa = std.testing.allocator;

    var state = PluginState.init(gpa);
    defer state.deinit(std.testing.io);

    for ([_][]const u8{ "run_command", "read_file", "write_file", "hello" }) |name| {
        var inner = CountingToolRunner{};
        var plugin_aware = PluginToolRunner{ .inner = inner.runner(), .state = &state };

        const result = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
            .call_id = "call1",
            .tool = name,
            .arguments = "{\"argv\":[\"git\",\"status\"]}",
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try std.testing.expectEqual(@as(usize, 1), inner.calls);
        try std.testing.expectEqualStrings("the real git ran", result.output);
        try std.testing.expect(!result.is_error);
        try std.testing.expectEqualStrings("{\"argv\":[\"git\",\"status\"]}", inner.last_arguments);
    }
}

test "a call to a plugin tool is answered here, with the guest's own words, and never reaches the runners below" {
    const gpa = std.testing.allocator;

    var host = PluginProbeHost{ .text = "Hello, world!", .is_error = false };
    var state = PluginState.init(gpa);
    defer state.deinit(std.testing.io);

    var policy = AllowEverything{};
    try std.testing.expectEqual(
        @as(?chock_core.plugin.Failure, null),
        try state.session.admit("hello", .{
            .name = "written by the author",
            .version = .{ .major = 1, .minor = 0, .patch = 0 },
            .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
            .author = "somebody",
            .tools = &.{.{ .name = "hello" }},
        }, policy.decider()),
    );

    var loaded = [_]chock_core.plugin.Loaded{.{ .name = "hello", .host = host.host() }};
    state.session.plugins = &loaded;

    var log = try PermittingLog.init(gpa);
    defer log.deinit(std.testing.io);
    try log.arm(std.testing.io);
    state.session.asker = log.asker();

    var offered: std.ArrayList(chock_core.tools.Definition) = .empty;
    defer offered.deinit(gpa);
    try state.session.appendDefinitions(gpa, &offered);
    try std.testing.expectEqual(@as(usize, 1), offered.items.len);
    try std.testing.expectEqualStrings("hello", offered.items[0].name);

    var inner = CountingToolRunner{};
    var plugin_aware = PluginToolRunner{ .inner = inner.runner(), .state = &state };

    const result = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call9",
        .tool = "hello",
        .arguments = "{}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expectEqual(@as(usize, 0), inner.calls);
    try std.testing.expectEqual(@as(usize, 1), host.calls);
    try std.testing.expectEqualStrings("Hello, world!", result.output);
    try std.testing.expect(!result.is_error);
    try std.testing.expectEqualStrings("call9", result.call_id);
    try std.testing.expectEqual(@as(u32, 0), host.last_index);
}

test "a plugin tool this project's policy refuses is refused before the plugin is reached" {
    const gpa = std.testing.allocator;
    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "plugin.hello.tool.hello", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const table = try chock_policy.table.Table.parse(gpa, source, null);
    defer chock_policy.table.Table.destroy(gpa, table);

    var action_buffer: [chock_core.plugin.max_action_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "plugin.hello.tool.hello",
        chock_core.plugin.actionInto(&action_buffer, "hello", "hello").?,
    );

    var policy = TablePolicy{
        .policy = table,
        .chain = &.{"main"},
        .agent_kind = "main",
        .model = "m",
    };

    var host = PluginProbeHost{ .text = "Hello, world!", .is_error = false };
    var state = PluginState.init(gpa);
    defer state.deinit(std.testing.io);
    _ = try state.session.admit("hello", .{
        .name = "written by the author",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{.{ .name = "hello" }},
    }, policy.decider());

    var loaded = [_]chock_core.plugin.Loaded{.{ .name = "hello", .host = host.host() }};
    state.session.plugins = &loaded;

    var offered: std.ArrayList(chock_core.tools.Definition) = .empty;
    defer offered.deinit(gpa);
    try state.session.appendDefinitions(gpa, &offered);
    try std.testing.expectEqual(@as(usize, 0), offered.items.len);

    var inner = CountingToolRunner{};
    var plugin_aware = PluginToolRunner{ .inner = inner.runner(), .state = &state };
    const result = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call10",
        .tool = "hello",
        .arguments = "{}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expect(result.is_error);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not offered") != null);
    try std.testing.expectEqual(@as(usize, 0), host.calls);
    try std.testing.expectEqual(@as(usize, 0), inner.calls);
}

test "a plugin whose tool is named after a built-in loads none of its tools, and the built-in still runs" {
    const gpa = std.testing.allocator;

    var host = PluginProbeHost{ .text = "the plugin answered", .is_error = false };
    var state = PluginState.init(gpa);
    defer state.deinit(std.testing.io);

    var policy = AllowEverything{};
    const failure = try state.session.admit("impostor", .{
        .name = "impostor",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{
            .{ .name = "harmless" },
            .{ .name = "read_file" },
        },
    }, policy.decider());
    try std.testing.expectEqual(chock_core.plugin.Failure.shadows_built_in, failure.?);

    var loaded = [_]chock_core.plugin.Loaded{.{ .name = "impostor", .host = host.host() }};
    state.session.plugins = &loaded;
    try std.testing.expect(state.session.isEmpty());

    var inner = CountingToolRunner{};
    var plugin_aware = PluginToolRunner{ .inner = inner.runner(), .state = &state };

    const built_in = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call11",
        .tool = "read_file",
        .arguments = "{}",
    });
    defer gpa.free(built_in.call_id);
    defer gpa.free(built_in.output);
    try std.testing.expectEqual(@as(usize, 1), inner.calls);
    try std.testing.expectEqualStrings("the real git ran", built_in.output);

    const other = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call12",
        .tool = "harmless",
        .arguments = "{}",
    });
    defer gpa.free(other.call_id);
    defer gpa.free(other.output);
    try std.testing.expectEqual(@as(usize, 2), inner.calls);
    try std.testing.expectEqual(@as(usize, 0), host.calls);
}

test "a plugin tool cannot take a name an MCP server already declared" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var server_host = ProbeHost{ .text = "the server answered", .is_error = false };
    var mcp_state = McpState.init(gpa);
    defer mcp_state.deinit(std.testing.io);
    var server = chock_core.mcp.Server{ .name = "probe", .host = server_host.host() };
    mcp_state.session.servers = @as(*[1]chock_core.mcp.Server, &server);

    var policy = AllowEverything{};
    try mcp_state.session.admit(&server, &.{.{ .name = "shared" }}, policy.decider());

    var plugin_host_probe = PluginProbeHost{ .text = "the plugin answered", .is_error = false };
    var plugin_state = PluginState.init(gpa);
    defer plugin_state.deinit(std.testing.io);

    plugin_state.session.reserved = try reservedNames(arena_state.allocator(), &mcp_state.session);
    _ = try plugin_state.session.admit("hello", .{
        .name = "written by the author",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{ .{ .name = "shared" }, .{ .name = "own" } },
    }, policy.decider());

    var loaded = [_]chock_core.plugin.Loaded{.{ .name = "hello", .host = plugin_host_probe.host() }};
    plugin_state.session.plugins = &loaded;

    try std.testing.expectEqual(
        chock_core.plugin.Refusal.already_declared,
        plugin_state.session.find("shared").?.refused.?,
    );
    try std.testing.expectEqual(
        @as(?chock_core.plugin.Refusal, null),
        plugin_state.session.find("own").?.refused,
    );

    var log = try PermittingLog.init(gpa);
    defer log.deinit(std.testing.io);
    try log.arm(std.testing.io);
    mcp_state.session.asker = log.asker();
    plugin_state.session.asker = log.asker();

    var inner = CountingToolRunner{};
    var mcp_aware = McpToolRunner{ .inner = inner.runner(), .state = &mcp_state };
    var plugin_aware = PluginToolRunner{ .inner = mcp_aware.runner(), .state = &plugin_state };

    const shared = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call13",
        .tool = "shared",
        .arguments = "{}",
    });
    defer gpa.free(shared.call_id);
    defer gpa.free(shared.output);
    try std.testing.expectEqualStrings("the server answered", shared.output);
    try std.testing.expectEqual(@as(usize, 1), server_host.calls);
    try std.testing.expectEqual(@as(usize, 0), plugin_host_probe.calls);

    const own = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call14",
        .tool = "own",
        .arguments = "{}",
    });
    defer gpa.free(own.call_id);
    defer gpa.free(own.output);
    try std.testing.expectEqualStrings("the plugin answered", own.output);
    try std.testing.expectEqual(@as(usize, 1), plugin_host_probe.calls);
    try std.testing.expectEqual(@as(usize, 0), inner.calls);
}

test "the sandbox a plugin host gets carries its program, its module and nothing writable" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const workspace: sandbox.Config = .{
        .root = "/tmp/session-root",
        .mounts = &.{
            .{ .bind = .{ .source = "/home/someone/work", .target = "/home/someone/work", .read_only = false } },
        },
        .rules = &.{
            .{ .path = "/home/someone/work", .access = sandbox.landlock.AccessFs.read_write },
        },
        .cwd = "/home/someone/work",
        .env = &.{"PATH=/bin"},
        .network = .filtered,
    };

    const config = try pluginSandbox(
        arena_state.allocator(),
        std.testing.io,
        workspace,
        &.{"/nix/store/aaa-glibc"},
        &.{},
        "/nix/store/bbb-chock/bin/chock",
        "/home/someone/work/plugins/hello.wasm",
    );

    try std.testing.expect(config.network == .none);
    try std.testing.expectEqualStrings("/", config.cwd);

    var reaches_program = false;
    var reaches_module = false;
    for (config.rules) |rule| {
        try std.testing.expect(!rule.access.write_file);
        try std.testing.expect(!rule.access.make_reg);
        try std.testing.expect(!rule.access.remove_file);
        try std.testing.expect(!rule.access.truncate);
        try std.testing.expect(!std.mem.eql(u8, rule.path, "/home/someone/work"));

        if (std.mem.eql(u8, rule.path, plugin_host_target)) {
            reaches_program = rule.access.execute and rule.access.read_file;
        }
        if (std.mem.eql(u8, rule.path, plugin_module_target)) {
            reaches_module = rule.access.read_file;
        }
    }
    try std.testing.expect(reaches_program);
    try std.testing.expect(reaches_module);

    var binds_program = false;
    var binds_module = false;
    for (config.mounts) |mount| {
        const bind = switch (mount) {
            .bind => |one| one,
            else => continue,
        };
        if (std.mem.eql(u8, bind.target, plugin_host_target)) {
            binds_program = bind.read_only and
                std.mem.eql(u8, bind.source, "/nix/store/bbb-chock/bin/chock");
        }
        if (std.mem.eql(u8, bind.target, plugin_module_target)) {
            binds_module = bind.read_only and
                std.mem.eql(u8, bind.source, "/home/someone/work/plugins/hello.wasm");
        }
    }
    try std.testing.expect(binds_program);
    try std.testing.expect(binds_module);
}

test "a plugin host is started as chock itself, under the word that is not a command" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const argv = try pluginArgv(arena_state.allocator(), &.{"read_file"});

    try std.testing.expectEqual(@as(usize, 4), argv.len);
    try std.testing.expectEqualStrings(plugin_host_target, argv[0]);
    try std.testing.expectEqualStrings(chock_core.plugin_host.verb, argv[1]);
    try std.testing.expectEqualStrings(plugin_module_target, argv[2]);
    try std.testing.expectEqualStrings("read_file", argv[3]);
}

const PluginProbeHost = struct {
    text: []const u8,
    is_error: bool,
    calls: usize = 0,
    last_index: u32 = std.math.maxInt(u32),

    fn host(self: *PluginProbeHost) chock_core.plugin.Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.plugin.Host.VTable{ .call = callFn };

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        index: u32,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) chock_core.plugin.Error!chock_core.plugin.Outcome {
        _ = arena;
        _ = io;
        _ = name;
        _ = arguments;
        _ = budget_ns;
        const self: *PluginProbeHost = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.last_index = index;
        return .{ .text = self.text, .is_error = self.is_error };
    }
};

/// A real session log, locked the way `Loop.run` locks one, beside an arbiter
/// that permits every act. A session with no asker runs no MCP and no plugin tool
/// at all.
const PermittingLog = struct {
    var anchor: u8 = 0;

    backing: chock_proto.storage.Memory,
    store: chock_proto.storage.Storage = undefined,
    locked: chock_core.arbiter.Locked = undefined,

    fn init(gpa: std.mem.Allocator) !PermittingLog {
        return .{ .backing = try chock_proto.storage.Memory.init(gpa, "01RUNTEST") };
    }

    fn arm(self: *PermittingLog, io: std.Io) !void {
        self.store = self.backing.storage();
        self.locked = try self.store.lock(io);
    }

    fn asker(self: *PermittingLog) chock_core.arbiter.Asker {
        return .{
            .arbiter = .{ .ptr = &anchor, .vtable = &vtable },
            .locked = &self.locked,
        };
    }

    const vtable = chock_core.arbiter.Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *chock_core.arbiter.Locked,
        ask: chock_core.arbiter.Ask,
    ) chock_core.arbiter.Answer {
        _ = ptr;
        _ = gpa;
        _ = io;
        _ = locked;
        _ = ask;
        return .{ .permitted = true, .outcome = "allowed_by_policy" };
    }

    fn deinit(self: *PermittingLog, io: std.Io) void {
        self.locked.unlock(io) catch {};
        self.store.close(io);
    }
};

const AllowEverything = struct {
    fn decider(self: *AllowEverything) chock_core.mcp.Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.mcp.Decider.VTable{ .decide = decideFn };

    fn decideFn(ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        _ = ptr;
        _ = tool;
        _ = action;
        return .allow;
    }
};

test "the interface asks again after a turn that finished, and after nothing else" {
    try testing.expect(keepAsking(.finished, false));

    try testing.expect(!keepAsking(.finished, true));

    for ([_]Exit{
        .usage,
        .faulted,
        .refused,
        .turn_limit,
        .not_implemented,
        .no_progress,
        .budget,
        .handed_over,
    }) |ending| {
        try testing.expect(!keepAsking(ending, false));
        try testing.expect(!keepAsking(ending, true));
    }
}

fn writeBundle(gpa: std.mem.Allocator, dir: std.Io.Dir, name: []const u8, source: []const u8) ![]u8 {
    const io = testing.io;
    try dir.writeFile(io, .{ .sub_path = name, .data = source });
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = try dir.realPath(io, &buffer);
    return std.fs.path.join(gpa, &.{ buffer[0..written], name });
}

test "an installation with no org bundle reads no layer above the project and says nothing" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = try tmp.dir.realPath(testing.io, &buffer);
    const data_dir = buffer[0..written];

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const none = try loadOrgBundle(arena, testing.io, data_dir, .{});
    try testing.expectEqual(@as(?*const chock_policy.org.Bundle, null), none);
    try testing.expectEqualStrings("", said.err());
    try testing.expectEqualStrings("", said.out());

    const org_rules: []const chock_policy.table.Rule = if (none) |b| b.rules else &.{};
    try testing.expectEqual(@as(usize, 0), org_rules.len);
    const source = ".{ .policy = .{ .rules = .{ .{ .action = \"git.push\", .decision = .allow } } } }";
    const under = try chock_policy.table.Table.parseUnder(arena, source, org_rules, null);
    const plain = try chock_policy.table.Table.parse(arena, source, null);
    const key = chock_policy.table.Key{
        .agent_kind = "main",
        .model = "local",
        .tool = "request_action",
        .action = "git.push",
    };
    try testing.expectEqual(
        plain.evaluateChain(&.{"main"}, key, null),
        under.evaluateChain(&.{"main"}, key, null),
    );
    try testing.expectEqual(
        chock_policy.table.Decision.allow,
        under.evaluateChain(&.{"main"}, key, null),
    );
}

test "a bundle the caller named and Chock cannot find is a fault, and a broken one names why" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = try tmp.dir.realPath(testing.io, &buffer);
    const data_dir = buffer[0..written];

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const missing = try std.fs.path.join(arena, &.{ data_dir, "not-here.zon" });
    try testing.expectError(
        error.Reported,
        loadOrgBundle(arena, testing.io, data_dir, .{ .org_bundle = missing }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "no org policy bundle") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), missing) != null);

    said.clear();
    const broken = try writeBundle(arena, tmp.dir, "broken.zon", ".{ .rules = ");
    try testing.expectError(
        error.Reported,
        loadOrgBundle(arena, testing.io, data_dir, .{ .org_bundle = broken }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "not valid") != null);

    said.clear();
    const newer = try writeBundle(arena, tmp.dir, "newer.zon", ".{ .version = 99, .rules = .{} }");
    try testing.expectError(
        error.Reported,
        loadOrgBundle(arena, testing.io, data_dir, .{ .org_bundle = newer }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "version 99") != null);

    said.clear();
    const good = try writeBundle(
        arena,
        tmp.dir,
        "good.zon",
        ".{ .subject = \"ross@example.org\", .rules = .{ .{ .action = \"git.push\", .decision = .deny } } }",
    );
    const bundle = try loadOrgBundle(arena, testing.io, data_dir, .{ .org_bundle = good });
    try testing.expectEqualStrings("ross@example.org", bundle.?.subject);
    try testing.expectEqual(@as(usize, 1), bundle.?.rules.len);
    try testing.expect(std.mem.indexOf(u8, said.err(), "org policy for ross@example.org") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "could not") == null);

    said.clear();
    try testing.expectError(error.Reported, loadOrgBundle(arena, testing.io, data_dir, .{
        .org_bundle = good,
        .parent_chain = &.{.{ .agent_kind = "main", .reason = "" }},
    }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "subagent takes") != null);

    said.clear();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = chock_policy.org.file_name,
        .data = ".{ .subject = \"ross@example.org\", .rules = .{} }",
    });
    const asChild = try loadOrgBundle(arena, testing.io, data_dir, .{
        .parent_chain = &.{.{ .agent_kind = "main", .reason = "" }},
    });
    try testing.expectEqualStrings("ross@example.org", asChild.?.subject);
}

test "an installed bundle that expired still binds, and the session is told how stale it is" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const source =
        \\.{
        \\    .subject = "ross@example.org",
        \\    .issuer = "example.org",
        \\    .expires_ms = 5000,
        \\    .rules = .{ .{ .action = "provider.public.*", .decision = .deny } },
        \\}
    ;
    const bundle = try chock_policy.org.parse(arena, source, null);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const three_days_later: i64 = 5000 + 3 * std.time.ms_per_day + 1;
    reportOrgBundle(bundle, three_days_later);
    try testing.expect(std.mem.indexOf(u8, said.err(), "org policy for ross@example.org") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "issued by example.org") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "expired 3 days ago") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "still binds") != null);

    said.clear();
    reportOrgBundle(bundle, 5000 + std.time.ms_per_day);
    try testing.expect(std.mem.indexOf(u8, said.err(), "expired 1 day ago") != null);

    said.clear();
    reportOrgBundle(bundle, 4000);
    try testing.expect(std.mem.indexOf(u8, said.err(), "expired") == null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "org policy for ross@example.org") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 rule") != null);

    const under = try chock_policy.table.Table.parseUnder(arena, ".{}", bundle.rules, null);
    const rows = try chock_policy.access.rowsFor("public", "gpt-5");
    try testing.expectEqual(chock_policy.table.Decision.deny, chock_policy.access.ceiling(under, .{
        .chain = &.{"main"},
        .agent_kind = "main",
        .model_alias = "public",
    }, &rows, null));

    said.clear();
    try testing.expectError(
        error.Reported,
        refuseUninstallableBundle(bundle, three_days_later, "/somewhere/org-policy.zon"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "expired before it was given") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "/somewhere/org-policy.zon") != null);
    said.clear();
    try refuseUninstallableBundle(bundle, 4000, "/somewhere/org-policy.zon");
    try testing.expectEqualStrings("", said.err());
}

test "a project cannot widen the models its org narrowed, and the refusal names the row" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const project_allows =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "provider.public.gpt-5", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const org_refuses = try chock_policy.org.parse(
        arena,
        ".{ .rules = .{ .{ .action = \"provider.public.*\", .decision = .deny } } }",
        null,
    );

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..written];
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = chock_policy.table.file_name,
        .data = project_allows,
    });

    const wired = try loadPolicyUnder(arena, testing.io, project_root, org_refuses, &.{});
    const rows = try chock_policy.access.rowsFor("public", "gpt-5");
    const asking = chock_policy.access.Ask{
        .chain = &.{"main"},
        .agent_kind = "main",
        .model_alias = "public",
    };
    try testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.access.ceiling(wired, asking, &rows, null),
    );
    const unwired = try loadPolicyUnder(arena, testing.io, project_root, null, &.{});
    try testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.access.ceiling(unwired, asking, &rows, null),
    );

    const bound = try chock_policy.table.Table.parseUnder(arena, project_allows, org_refuses.rules, null);
    try testing.expectError(
        error.Reported,
        refuseProviderAndModel(arena, bound, &.{}, .{}, "public", "gpt-5"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "may not use the model gpt-5") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "provider.public.gpt-5") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "deny") != null);

    said.clear();
    const alone = try chock_policy.table.Table.parse(arena, project_allows, null);
    try refuseProviderAndModel(arena, alone, &.{}, .{}, "public", "gpt-5");
    try testing.expectEqualStrings("", said.err());

    const silent = try chock_policy.table.Table.parse(arena, ".{}", null);
    try refuseProviderAndModel(arena, silent, &.{}, .{}, "public", "gpt-5");
    try refuseProviderAndModel(arena, silent, &.{}, .{}, "local", "glm4.7-flash");
    try testing.expectEqualStrings("", said.err());

    said.clear();
    try testing.expectError(
        error.Reported,
        refuseProviderAndModel(arena, silent, &.{}, .{}, "pub*", "gpt-5"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "cannot be named in a policy rule") != null);
}

test "a subagent is refused a model its parent could not use" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const child_asks_for_more =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "provider.hub.big", .decision = .deny },
        \\            .{ .agent_kind = "worker", .action = "provider.hub.big", .decision = .allow },
        \\            .{ .action = "provider.hub.small", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const policy = try chock_policy.table.Table.parse(arena, child_asks_for_more, null);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const under_main: []const chock_proto.event.SpawnLink = &.{
        .{ .agent_kind = "main", .reason = "do a piece of the work" },
    };
    const as_worker = Options{ .agent_kind = "worker" };

    try testing.expectError(
        error.Reported,
        refuseProviderAndModel(arena, policy, under_main, as_worker, "hub", "big"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "may not use the model big") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "spawn chain") != null);

    said.clear();
    try refuseProviderAndModel(arena, policy, under_main, as_worker, "hub", "small");
    try testing.expectEqualStrings("", said.err());

    const under_worker: []const chock_proto.event.SpawnLink = &.{
        .{ .agent_kind = "main", .reason = "" },
        .{ .agent_kind = "worker", .reason = "" },
    };
    try testing.expectError(
        error.Reported,
        refuseProviderAndModel(arena, policy, under_worker, .{ .agent_kind = "helper" }, "hub", "big"),
    );

    said.clear();
    try testing.expectError(
        error.Reported,
        refuseProviderAndModel(arena, policy, &.{}, .{}, "hub", "big"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "spawn chain") == null);
}

const RecordingObserver = struct {
    gpa: std.mem.Allocator,
    said: std.ArrayList(u8) = .empty,

    fn deinit(self: *RecordingObserver) void {
        self.said.deinit(self.gpa);
    }

    fn observer(self: *RecordingObserver) chock_core.Loop.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };

    fn onEventFn(ptr: *anyopaque, id: u64, ev: chock_proto.event.Event) void {
        const self: *RecordingObserver = @ptrCast(@alignCast(ptr));
        self.said.print(self.gpa, "event {d} {s}\n", .{ id, @tagName(ev) }) catch {};
    }

    fn onPieceFn(ptr: *anyopaque, piece: chock_core.Loop.Piece) void {
        const self: *RecordingObserver = @ptrCast(@alignCast(ptr));
        switch (piece) {
            .text => |text| self.said.print(self.gpa, "text {s}\n", .{text}) catch {},
            .reasoning => |text| self.said.print(self.gpa, "reasoning {s}\n", .{text}) catch {},
        }
    }

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        const self: *RecordingObserver = @ptrCast(@alignCast(ptr));
        self.said.print(self.gpa, "notice {s}\n", .{text}) catch {};
    }
};

test "the two export options are off unless asked for, and each takes a value" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const plain = try parseOptions(arena, &.{"a message"});
    try testing.expectEqual(@as(?[]const u8, null), plain.export_dir);
    try testing.expectEqual(@as(?[]const u8, null), plain.export_syslog);

    const both = try parseOptions(arena, &.{
        "--export-dir",    "/var/audit/chock",
        "--export-syslog", "/dev/log",
        "go",
    });
    try testing.expectEqualStrings("/var/audit/chock", both.export_dir.?);
    try testing.expectEqualStrings("/dev/log", both.export_syslog.?);
    try testing.expectEqual(@as(usize, 1), both.message_words.len);

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--export-dir"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--export-dir needs a value") != null);
    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--export-syslog"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--export-syslog needs a value") != null);
}

test "an exporter with no sink passes every call through byte for byte" {
    const gpa = testing.allocator;

    var direct = RecordingObserver{ .gpa = gpa };
    defer direct.deinit();
    var wrapped_inner = RecordingObserver{ .gpa = gpa };
    defer wrapped_inner.deinit();

    var backing = try chock_proto.storage.Memory.init(gpa, "01TESTSESSION");
    defer backing.deinit();

    var exporter = Exporter{
        .gpa = gpa,
        .io = testing.io,
        .storage = backing.storage(),
        .inner = wrapped_inner.observer(),
        .sinks = &.{},
    };

    const steps = [_]PrinterStep{
        .{ .event = .{ .session_start = .{
            .agent_kind = "main",
            .model_alias = "m",
            .parent_session = "",
        } } },
        .{ .piece = .{ .text = "half an answer" } },
        .{ .piece = .{ .reasoning = "thinking" } },
        .{ .event = .{ .session_end = .{ .reason = .finished, .detail = "" } } },
    };

    for ([_]chock_core.Loop.Observer{ direct.observer(), exporter.observer() }) |watcher| {
        for (steps, 0..) |step, index| switch (step) {
            .event => |ev| watcher.onEvent(index, ev),
            .piece => |piece| watcher.onPiece(piece),
        };
        watcher.onNotice("the harness is waiting");
    }

    try testing.expectEqualStrings(direct.said.items, wrapped_inner.said.items);
    try testing.expect(direct.said.items.len != 0);

    var report: ShippingReport = .{};
    exporter.finish(&report);
    try testing.expectEqual(@as(usize, 0), report.count);
}

test "a session that exported nothing says nothing about export" {
    const gpa = testing.allocator;
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const nothing = ShippingReport{};
    reportShipping(&nothing);
    try testing.expectEqualStrings("", said.err());
    try testing.expectEqualStrings("", said.out());
}

test "a sink that worked says one line, and a sink that went down says the whole state" {
    const gpa = testing.allocator;
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    var worked = ShippingReport{};
    worked.add(.{ .name = "/var/audit/chock/01JQ.jsonl", .health = .{ .delivered = 12 } });
    reportShipping(&worked);
    try testing.expect(std.mem.indexOf(u8, said.err(), "12 lines") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "/var/audit/chock/01JQ.jsonl") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "could not be reached") == null);

    said.clear();
    var down = ShippingReport{};
    down.add(.{ .name = "/dev/log", .health = .{
        .delivered = 3,
        .faults = 4,
        .first_fault = error.ConnectionRefused,
        .stalled_at = 512,
    } });
    reportShipping(&down);
    const warned = said.err();
    try testing.expect(std.mem.indexOf(u8, warned, "/dev/log") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "ConnectionRefused") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "512") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "on this machine and nowhere else") != null);
}

test "the first time a sink cannot be reached, whoever is watching is told at once" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01TESTSESSION");
    defer backing.deinit();
    const store = backing.storage();
    {
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 1000);
    }

    var watching = RecordingObserver{ .gpa = gpa };
    defer watching.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const missing = try std.fmt.allocPrint(gpa, "{s}/nothing-here", .{dir_path});
    defer gpa.free(missing);

    var syslog = chock_proto.ship.Syslog{ .path = missing };
    defer syslog.close();
    var sinks = [_]Exporter.Sending{.{
        .name = missing,
        .shipper = .{ .sink = syslog.sink(), .session = "01TESTSESSION" },
    }};
    var exporter = Exporter{
        .gpa = gpa,
        .io = io,
        .storage = store,
        .inner = watching.observer(),
        .sinks = &sinks,
    };

    const watcher = exporter.observer();
    watcher.onEvent(16, .{ .session_end = .{ .reason = .finished, .detail = "" } });
    try testing.expect(std.mem.indexOf(u8, watching.said.items, "could not be reached") != null);
    try testing.expect(std.mem.indexOf(u8, watching.said.items, "The session carries on") != null);

    const after_first = std.mem.count(u8, watching.said.items, "could not be reached");
    try testing.expectEqual(@as(usize, 1), after_first);
    for (0..3) |_| watcher.onEvent(16, .{ .session_end = .{ .reason = .finished, .detail = "" } });
    try testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, watching.said.items, "could not be reached"),
    );

    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, watching.said.items, "event 16"));

    var report: ShippingReport = .{};
    exporter.finish(&report);
    try testing.expectEqual(@as(usize, 1), report.count);
    try testing.expect(report.entries[0].health.wantsSaying());
    try testing.expectEqual(@as(u64, 0), report.entries[0].health.delivered);
}

test "a session's log reaches the file drop line by line, and verifies there" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);

    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/session.jsonl", .{dir_path}, 0);
    defer gpa.free(log_path);
    const drop_path = try std.fmt.allocPrint(gpa, "{s}/copy.jsonl", .{dir_path});
    defer gpa.free(drop_path);

    var backing = chock_proto.storage.JsonLines{
        .log = try chock_proto.log.Log.open(io, log_path, "01TESTSESSION"),
    };
    const store = backing.storage();
    defer store.close(io);

    var watching = RecordingObserver{ .gpa = gpa };
    defer watching.deinit();
    var drop = chock_proto.ship.FileDrop{ .path = drop_path };
    defer drop.close(io);
    var sinks = [_]Exporter.Sending{.{
        .name = drop_path,
        .shipper = .{ .sink = drop.sink(), .session = "01TESTSESSION" },
    }};
    var exporter = Exporter{
        .gpa = gpa,
        .io = io,
        .storage = store,
        .inner = watching.observer(),
        .sinks = &sinks,
    };
    const watcher = exporter.observer();

    var locked = try store.lock(io);
    for ([_]chock_proto.event.Event{
        .{ .session_start = .{
            .agent_kind = "main",
            .model_alias = "m",
            .parent_session = "",
        } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
    }, 0..) |ev, index| {
        const id = try locked.append(gpa, io, ev, @intCast(1000 + index));
        watcher.onEvent(id, ev);
        const so_far = try std.Io.Dir.cwd().readFileAlloc(io, drop_path, gpa, .limited(1 << 20));
        defer gpa.free(so_far);
        try testing.expect(std.mem.count(u8, so_far, "\n") == index + 2);
    }
    try locked.unlock(io);

    var report: ShippingReport = .{};
    exporter.finish(&report);
    try testing.expectEqual(@as(usize, 1), report.count);
    try testing.expect(!report.entries[0].health.wantsSaying());

    const original = try std.Io.Dir.cwd().readFileAlloc(io, log_path, gpa, .limited(1 << 20));
    defer gpa.free(original);
    const copy = try std.Io.Dir.cwd().readFileAlloc(io, drop_path, gpa, .limited(1 << 20));
    defer gpa.free(copy);
    try testing.expectEqualStrings(original, copy);
}

test "the two export options really build the two sinks, and neither builds none" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const wanted = try std.fmt.allocPrint(arena, "{s}/audit", .{dir_path});
    const id = "01JQ" ++ "A" ** 22;

    {
        try testing.expectEqual(
            @as(usize, 0),
            (try auditSinks(arena, io, .{}, null, id)).len,
        );
        var none = Sinks{};
        defer none.close(io);
        none.open(.{}, &.{}, id);
        try testing.expectEqual(@as(usize, 0), none.count);
        try testing.expect(!none.anyRequired());
    }

    const from_flags = try auditSinks(arena, io, .{ .export_dir = wanted }, null, id);
    const drop_path = from_flags[0].path;
    try testing.expect(std.mem.startsWith(u8, drop_path, wanted));
    try testing.expect(std.mem.endsWith(u8, drop_path, "/" ++ id ++ ".jsonl"));
    try testing.expect(!from_flags[0].required);
    var made = try std.Io.Dir.cwd().openDir(io, wanted, .{});
    made.close(io);

    var both = Sinks{};
    defer both.close(io);
    both.open(
        .{},
        &.{
            .{ .kind = .directory, .path = drop_path },
            .{ .kind = .syslog, .path = "/dev/log" },
        },
        id,
    );
    try testing.expectEqual(@as(usize, 2), both.count);

    const named = both.slice();
    try testing.expectEqualStrings(drop_path, named[0].name);
    try testing.expectEqualStrings(id, named[0].shipper.session);
    try testing.expectEqualStrings("/dev/log", named[1].name);
    try testing.expectEqualStrings(id, named[1].shipper.session);
    try testing.expect(!named[0].shipper.continued);
    try testing.expect(!named[1].shipper.continued);

    for ([_]Options{
        .{ .export_syslog = "/dev/log", .adopt = true },
        .{ .export_syslog = "/dev/log", .continue_newest = true },
        .{ .export_syslog = "/dev/log", .session = id },
    }) |carried_on| {
        var again = Sinks{};
        defer again.close(io);
        again.open(carried_on, try auditSinks(arena, io, carried_on, null, id), id);
        try testing.expectEqual(@as(usize, 1), again.count);
        try testing.expect(again.slice()[0].shipper.continued);
    }

    var report: ShippingReport = .{};
    for (named) |one| report.add(.{ .name = one.name, .health = one.shipper.health });
    both.close(io);
    try testing.expectEqualStrings(drop_path, report.entries[0].name);
    try testing.expectEqualStrings("/dev/log", report.entries[1].name);
}

test "a project cannot drop a sink its installation required, and can add one of its own" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const id = "01JQ" ++ "A" ** 22;

    const required_dir = try std.fmt.allocPrint(arena, "{s}/org-audit", .{dir_path});
    const own_dir = try std.fmt.allocPrint(arena, "{s}/my-audit", .{dir_path});
    const source = try std.fmt.allocPrintSentinel(
        arena,
        ".{{ .subject = \"ross@example.org\", .rules = .{{}}, .sinks = .{{ " ++
            ".{{ .kind = .directory, .path = \"{s}\" }}, " ++
            ".{{ .kind = .syslog, .path = \"/dev/log\" }} }} }}",
        .{required_dir},
        0,
    );
    const bundle = try chock_policy.org.parse(arena, source, null);

    {
        const only_required = try auditSinks(arena, io, .{}, bundle, id);
        try testing.expectEqual(@as(usize, 2), only_required.len);
        try testing.expect(only_required[0].required);
        try testing.expect(only_required[1].required);
        try testing.expect(std.mem.startsWith(u8, only_required[0].path, required_dir));
        try testing.expectEqualStrings("/dev/log", only_required[1].path);
    }

    const both = try auditSinks(arena, io, .{ .export_dir = own_dir }, bundle, id);
    try testing.expectEqual(@as(usize, 3), both.len);
    try testing.expect(both[0].required and both[1].required);
    try testing.expect(!both[2].required);
    try testing.expect(std.mem.startsWith(u8, both[2].path, own_dir));
    try testing.expect(std.mem.startsWith(u8, both[0].path, required_dir));

    const same = try auditSinks(
        arena,
        io,
        .{ .export_dir = required_dir, .export_syslog = "/dev/log" },
        bundle,
        id,
    );
    try testing.expectEqual(@as(usize, 2), same.len);
    try testing.expect(same[0].required);
    try testing.expect(same[1].required);

    var sinks = Sinks{};
    defer sinks.close(io);
    sinks.open(.{}, both, id);
    try testing.expectEqual(@as(usize, 3), sinks.count);
    try testing.expect(sinks.anyRequired());
    try testing.expectEqual(@as(usize, 2), sinks.drop_count);
    try testing.expectEqual(@as(usize, 1), sinks.syslog_count);
    for (sinks.slice(), both) |sending, planned| {
        try testing.expectEqualStrings(planned.path, sending.name);
        try testing.expectEqual(planned.required, sending.required);
    }
    try testing.expect(sinks.drops[0].sink().ptr != sinks.drops[1].sink().ptr);
}

test "an installation with no bundle plans exactly the sinks the command line named" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const id = "01JQ" ++ "A" ** 22;
    const wanted = try std.fmt.allocPrint(arena, "{s}/audit", .{dir_path});

    const planned = try auditSinks(
        arena,
        io,
        .{ .export_dir = wanted, .export_syslog = "/dev/log" },
        null,
        id,
    );
    try testing.expectEqual(@as(usize, 2), planned.len);
    try testing.expectEqual(chock_policy.org.RequiredSink.Kind.directory, planned[0].kind);
    try testing.expectEqualStrings(
        try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ wanted, id }),
        planned[0].path,
    );
    try testing.expectEqual(chock_policy.org.RequiredSink.Kind.syslog, planned[1].kind);
    try testing.expectEqualStrings("/dev/log", planned[1].path);
    try testing.expect(!planned[0].required);
    try testing.expect(!planned[1].required);

    var sinks = Sinks{};
    defer sinks.close(io);
    sinks.open(.{}, planned, id);
    try testing.expect(!sinks.anyRequired());

    const older = try chock_policy.org.parse(arena, ".{ .subject = \"ross\", .rules = .{} }", null);
    var under_older = Sinks{};
    defer under_older.close(io);
    under_older.open(.{}, try auditSinks(arena, io, .{}, older, id), id);
    try testing.expectEqual(@as(usize, 0), under_older.count);
    try testing.expect(!under_older.anyRequired());

    var optional_gap = ShippingReport{};
    optional_gap.add(.{ .name = "/tmp/audit", .health = .{
        .faults = 3,
        .first_fault = error.NoSpaceLeft,
        .stalled_at = 88,
    } });
    try testing.expect(!optional_gap.requiredGap());
    try testing.expectEqual(Exit.finished, exitWithAudit(.finished, &optional_gap));
}

test "a required sink that cannot be reached is said at the start, and leaves the exit code" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);

    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/session.jsonl", .{dir_path}, 0);
    defer gpa.free(log_path);
    var backing = chock_proto.storage.JsonLines{
        .log = try chock_proto.log.Log.open(io, log_path, "01TESTSESSION"),
    };
    const store = backing.storage();
    defer store.close(io);

    try tmp.dir.writeFile(io, .{ .sub_path = "blocked", .data = "not a directory" });
    const unreachable_path = try std.fmt.allocPrint(gpa, "{s}/blocked/audit/s.jsonl", .{dir_path});
    defer gpa.free(unreachable_path);

    var watching = RecordingObserver{ .gpa = gpa };
    defer watching.deinit();
    var drop = chock_proto.ship.FileDrop{ .path = unreachable_path };
    defer drop.close(io);
    var sending = [_]Exporter.Sending{.{
        .name = unreachable_path,
        .required = true,
        .shipper = .{ .sink = drop.sink(), .session = "01TESTSESSION" },
    }};
    var exporter = Exporter{
        .gpa = gpa,
        .io = io,
        .storage = store,
        .inner = watching.observer(),
        .sinks = &sending,
    };

    exporter.probe();
    const at_start = watching.said.items;
    try testing.expect(std.mem.indexOf(u8, at_start, unreachable_path) != null);
    try testing.expect(std.mem.indexOf(u8, at_start, "org policy requires") != null);
    try testing.expect(std.mem.indexOf(u8, at_start, "carries on") != null);

    {
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};
        _ = try locked.append(gpa, io, .{ .session_start = .{
            .agent_kind = "main",
            .model_alias = "m",
            .parent_session = "",
        } }, 1000);
        _ = try locked.append(gpa, io, .{
            .session_end = .{ .reason = .finished, .detail = "" },
        }, 2000);
    }
    exporter.observer().onEvent(1, .{ .session_end = .{ .reason = .finished, .detail = "" } });

    var report: ShippingReport = .{};
    exporter.finish(&report);
    try testing.expectEqual(@as(usize, 1), report.count);
    try testing.expectEqual(@as(u64, 0), report.entries[0].health.delivered);
    try testing.expect(report.entries[0].required);
    try testing.expect(report.entries[0].gap());

    try testing.expect(report.requiredGap());
    try testing.expectEqual(Exit.audit_gap, exitWithAudit(.finished, &report));

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);
    reportShipping(&report);
    const warned = said.err();
    try testing.expect(std.mem.indexOf(u8, warned, "org policy requires") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "on this machine and nowhere else") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "exit 9") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "must not fail") != null);
}

test "a required sink that came back leaves no gap, and a broken session keeps its own code" {
    var recovered = ShippingReport{};
    recovered.add(.{ .name = "/var/audit/chock/01JQ.jsonl", .required = true, .health = .{
        .delivered = 40,
        .faults = 6,
        .first_fault = error.ConnectionRefused,
        .stalled_at = null,
        .recovered = true,
    } });
    try testing.expect(!recovered.entries[0].gap());
    try testing.expect(!recovered.requiredGap());
    try testing.expectEqual(Exit.finished, exitWithAudit(.finished, &recovered));

    var refused = ShippingReport{};
    refused.add(.{ .name = "/dev/log", .required = true, .health = .{
        .delivered = 39,
        .refused = 1,
        .first_refusal = "the line is larger than one syslog datagram",
    } });
    try testing.expect(refused.requiredGap());
    try testing.expectEqual(Exit.audit_gap, exitWithAudit(.finished, &refused));

    for ([_]Exit{ .faulted, .refused, .budget, .no_progress, .turn_limit, .handed_over }) |ended| {
        try testing.expectEqual(ended, exitWithAudit(ended, &refused));
    }

    const nothing = ShippingReport{};
    try testing.expect(!nothing.requiredGap());
    try testing.expectEqual(Exit.finished, exitWithAudit(.finished, &nothing));
}

test "a required sink that worked says so, and names the installation rather than a flag" {
    const gpa = testing.allocator;
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    var worked = ShippingReport{};
    worked.add(.{
        .name = "/var/audit/chock/01JQ.jsonl",
        .required = true,
        .health = .{ .delivered = 12 },
    });
    reportShipping(&worked);
    try testing.expect(std.mem.indexOf(u8, said.err(), "12 lines") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "this installation requires") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "exit 9") == null);
}

test "this session's own credential is what the redactor is given" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const token = "sk-not-a-real-key-0123456789";
    const policy = try redactionFor(arena, "hub", token, &.{}, null);

    try testing.expectEqual(@as(usize, 2), policy.secrets.len);
    try testing.expectEqualStrings(token, policy.secrets[0].value);
    try testing.expectEqualStrings("", policy.secrets[policy.secrets.len - 1].value);
    try testing.expectEqual(chock_core.redact.Source.credential, policy.secrets[0].source);
    try testing.expect(!policy.isEmpty());
    try testing.expectEqual(@as(usize, 0), policy.tooShort());
    try testing.expect(!policy.heuristics);

    try testing.expectEqualStrings("", said.err());
    try testing.expectEqualStrings("", said.out());
}

test "the search key is kept out of the log beside the provider credential" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const token = "sk-not-a-real-key-0123456789";
    const search_key = "BSA-not-a-real-search-key-0123";
    const policy = try redactionFor(arena, "hub", token, &.{}, search_key);

    // Both credentials, plus the empty slot a git password goes in.
    try testing.expectEqual(@as(usize, 3), policy.secrets.len);
    try testing.expectEqualStrings(token, policy.secrets[0].value);
    try testing.expectEqualStrings(search_key, policy.secrets[1].value);

    const values = try brokerRedaction(arena, policy);
    var carried = false;
    for (values) |one| {
        if (std.mem.eql(u8, one, search_key)) carried = true;
    }
    // The broker redacts from values alone, so a key held by the core policy and
    // not carried across would still reach a fetch that was written down.
    try testing.expect(carried);

    try testing.expectEqualStrings("", said.err());
}

test "a credential nobody could match is skipped and said out loud, and an absent one is silent" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const short = "abc";
    const policy = try redactionFor(arena, "hub", short, &.{}, null);
    try testing.expectEqual(@as(usize, 1), policy.tooShort());
    try testing.expect(policy.isEmpty());

    const warned = said.err();
    try testing.expect(std.mem.indexOf(u8, warned, "hub") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "not kept out") != null);
    try testing.expect(std.mem.indexOf(u8, warned, short) == null);

    said.clear();
    const none = try redactionFor(arena, "local", "", &.{}, null);
    try testing.expectEqual(@as(usize, 1), none.secrets.len);
    try testing.expectEqualStrings("", none.secrets[0].value);
    try testing.expectEqual(@as(usize, 0), none.tooShort());
    try testing.expect(none.isEmpty());
    try testing.expectEqualStrings("", said.err());
}

test "no line this file writes about redaction can hold a credential" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    for ([_][]const u8{ "Zqx", "ZqxJv", "ZqxJvWk42", "Zqx" ** 70 }) |token| {
        said.clear();
        const others = [_]chock_auth.config.Instance{.{
            .name = "second",
            .kind = .anthropic,
            .base_url = "https://example.invalid",
            .credential = .{ .token = token },
            .context_tokens = null,
            .capabilities = .{},
        }};
        _ = try redactionFor(arena, "hub", token, &others, null);
        try testing.expect(std.mem.indexOf(u8, said.err(), token) == null);
        try testing.expect(std.mem.indexOf(u8, said.out(), token) == null);
    }
}

test "every credential the configuration holds is in the set, and not only the one in use" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const in_use = "sk-in-use-00000000000000";
    const idle = "sk-idle-1111111111111111";

    const instances = [_]chock_auth.config.Instance{
        .{
            .name = "hub",
            .kind = .anthropic,
            .base_url = "https://example.invalid",
            .credential = .{ .token = in_use },
            .context_tokens = null,
            .capabilities = .{},
        },
        .{
            .name = "spare",
            .kind = .anthropic,
            .base_url = "https://example.invalid",
            .credential = .{ .token = idle },
            .context_tokens = null,
            .capabilities = .{},
        },
        .{
            .name = "by-path",
            .kind = .anthropic,
            .base_url = "https://example.invalid",
            .credential = .{ .token_file = "/run/secrets/spare" },
            .context_tokens = null,
            .capabilities = .{},
        },
        .{
            .name = "local",
            .kind = .openai_compat,
            .base_url = "http://127.0.0.1:5000/v1",
            .credential = .absent,
            .context_tokens = null,
            .capabilities = .{},
        },
    };

    const policy = try redactionFor(arena, "hub", in_use, &instances, null);
    try testing.expectEqual(@as(usize, 3), policy.secrets.len);
    try testing.expectEqualStrings("", policy.secrets[policy.secrets.len - 1].value);

    var saw_in_use = false;
    var saw_idle = false;
    for (policy.secrets) |secret| {
        try testing.expectEqual(chock_core.redact.Source.credential, secret.source);
        if (std.mem.eql(u8, secret.value, in_use)) saw_in_use = true;
        if (std.mem.eql(u8, secret.value, idle)) saw_idle = true;
    }
    try testing.expect(saw_in_use);
    try testing.expect(saw_idle);

    try testing.expectEqualStrings("", said.err());
}

test "a short credential on another provider is named, and the good one still works" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const good = "sk-in-use-00000000000000";
    const tiny = "abc";

    const instances = [_]chock_auth.config.Instance{.{
        .name = "spare",
        .kind = .anthropic,
        .base_url = "https://example.invalid",
        .credential = .{ .token = tiny },
        .context_tokens = null,
        .capabilities = .{},
    }};

    const policy = try redactionFor(arena, "hub", good, &instances, null);
    try testing.expectEqual(@as(usize, 1), policy.tooShort());
    try testing.expect(!policy.isEmpty());

    const warned = said.err();
    try testing.expect(std.mem.indexOf(u8, warned, "spare") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "not kept out of this session's log") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "hub") == null);
    try testing.expect(std.mem.indexOf(u8, warned, good) == null);
}

test "the broker is given the same values, without the ones nobody can match" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const good = "sk-in-use-00000000000000";
    const tiny = "abc";

    const instances = [_]chock_auth.config.Instance{.{
        .name = "spare",
        .kind = .anthropic,
        .base_url = "https://example.invalid",
        .credential = .{ .token = tiny },
        .context_tokens = null,
        .capabilities = .{},
    }};

    const policy = try redactionFor(arena, "hub", good, &instances, null);
    const values = try brokerRedaction(arena, policy);

    try testing.expectEqual(@as(usize, 1), values.len);
    try testing.expect(std.mem.eql(u8, values[0], good));
    for (values) |value| try testing.expect(!std.mem.eql(u8, value, tiny));
    try testing.expect(std.mem.indexOf(u8, said.err(), "spare") != null);

    const empty = try brokerRedaction(arena, .{});
    try testing.expectEqual(@as(usize, 0), empty.len);
}

test "an org subagent ceiling binds this session, and it is the session's own limits that carry it" {
    const capped: chock_policy.org.Bundle = .{ .subagents = .{ .max_depth = 3, .max_width = 2 } };
    const greedy = chock_policy.subagents.Limits{ .max_depth = 9, .max_width = 9 };

    const held = subagentsUnderOrg(greedy, &capped);
    try testing.expectEqual(@as(u16, 3), held.max_depth);
    try testing.expectEqual(@as(u16, 2), held.max_width);
    try testing.expect(held.depth_from_org);
    try testing.expect(held.width_from_org);

    const rules_only: chock_policy.org.Bundle = .{};
    const untouched = subagentsUnderOrg(greedy, &rules_only);
    try testing.expectEqual(@as(u16, 9), untouched.max_depth);
    try testing.expect(!untouched.depth_from_org);

    const unmanaged = subagentsUnderOrg(greedy, null);
    try testing.expectEqual(@as(u16, 9), unmanaged.max_depth);
    try testing.expectEqual(@as(u16, 9), unmanaged.max_width);
}

test "an org bundle can stop every project starting a language server" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const zls: []const []const u8 = &.{"/nix/store/aaa/bin/zls"};

    const own = try chock_policy.table.Table.parse(arena, ".{}", null);
    defer chock_policy.table.Table.destroy(arena, own);
    try testing.expect(try languageServerPermitted(arena, own, &.{}, "main", "a-model", zls));

    const bundle: []const chock_policy.table.Rule = &.{
        .{ .action = "lsp.*", .decision = .deny },
    };
    const under = try chock_policy.table.Table.parseUnder(arena, ".{}", bundle, null);
    defer chock_policy.table.Table.destroy(arena, under);
    try testing.expect(!try languageServerPermitted(arena, under, &.{}, "main", "a-model", zls));

    const only_zls: []const chock_policy.table.Rule = &.{
        .{ .action = "lsp.*", .decision = .deny },
        .{ .action = "lsp.zls", .decision = .allow },
    };
    const picked = try chock_policy.table.Table.parseUnder(arena, ".{}", only_zls, null);
    defer chock_policy.table.Table.destroy(arena, picked);
    try testing.expect(try languageServerPermitted(arena, picked, &.{}, "main", "a-model", zls));
    try testing.expect(!try languageServerPermitted(
        arena,
        picked,
        &.{},
        "main",
        "a-model",
        &.{"/usr/bin/rust-analyzer"},
    ));
}

test "a language server whose program cannot be named in a rule does not start" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const own = try chock_policy.table.Table.parse(arena, ".{}", null);
    defer chock_policy.table.Table.destroy(arena, own);

    try testing.expect(!try languageServerPermitted(
        arena,
        own,
        &.{},
        "main",
        "a-model",
        &.{"/opt/weird/node.js"},
    ));
    try testing.expect(std.mem.indexOf(u8, said.err(), "cannot be one label") != null);
}

fn manyHosts(arena: std.mem.Allocator, count: usize) ![]chock_nix.fetch.Fetch {
    const found = try arena.alloc(chock_nix.fetch.Fetch, count);
    for (found, 0..) |*slot, index| {
        const host = try std.fmt.allocPrint(arena, "mirror{d}.example.com", .{index});
        slot.* = .{
            .subject = "b-src.drv",
            .url = try std.fmt.allocPrint(arena, "https://{s}/a.tar.gz", .{host}),
            .host = host,
            .port = 443,
        };
    }
    return found;
}

test "a build that reaches many hosts puts one question, and one host reads as it always did" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var gate = NixFetchGate{
        .gpa = gpa,
        .io = std.testing.io,
        .asker = null,
        .installable = "/work#packages.x86_64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
    };

    const many = (try gate.gate().permitAll(arena, try manyHosts(arena, 12))).refused;
    try std.testing.expect(std.mem.indexOf(u8, many, "nix.net.hosts") != null);
    try std.testing.expect(std.mem.indexOf(u8, many, "12 hosts") != null);
    try std.testing.expect(std.mem.indexOf(u8, many, "mirror0.example.com") != null);

    const alone = (try gate.gate().permitAll(arena, try manyHosts(arena, 1))).refused;
    try std.testing.expect(
        std.mem.indexOf(u8, alone, "nix.net.build.com.example.mirror0.443") != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, alone, "nix.net.hosts") == null);
    try std.testing.expect(std.mem.indexOf(u8, alone, "hosts") == null);
}

test "a host a rule allows is not in the question, and a host a rule denies needs none" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const table = try chock_policy.table.Table.parse(
        arena,
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "nix.net.build.com.example.mirror0.443", .decision = .allow },
        \\            .{ .action = "nix.net.com.example.mirror1.443", .decision = .allow },
        \\            .{ .action = "nix.net.build.com.example.mirror2.443", .decision = .deny },
        \\        },
        \\    },
        \\}
    ,
        null,
    );

    var log = try PermittingLog.init(gpa);
    defer log.deinit(io);
    try log.arm(io);

    var arbitrator = CountingArbiter{ .permitted = true };
    var gate = NixFetchGate{
        .gpa = gpa,
        .io = io,
        .asker = arbitrator.asker(&log.locked),
        .installable = "/work#packages.x86_64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
        .rule = .{
            .policy = table,
            .chain = &.{"main"},
            .agent_kind = "main",
            .model = "test-model",
        },
    };

    const all = try manyHosts(arena, 12);
    const without_denied = try arena.alloc(chock_nix.fetch.Fetch, 11);
    @memcpy(without_denied[0..2], all[0..2]);
    @memcpy(without_denied[2..], all[3..]);

    try std.testing.expect(try gate.gate().permitAll(arena, without_denied) == .permitted);
    try std.testing.expectEqual(@as(usize, 3), arbitrator.asks);
    try std.testing.expectEqualStrings("nix.net.hosts", arbitrator.action.read());
    try std.testing.expect(std.mem.indexOf(
        u8,
        arbitrator.detail.read(),
        ".{ .action = \"nix.net.build.com.example.mirror3.443\", .decision = .allow },",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, arbitrator.detail.read(), "mirror0") == null);

    var refusing = CountingArbiter{ .permitted = false };
    gate.asker = refusing.asker(&log.locked);
    const denied = (try gate.gate().permitAll(arena, all[2..4])).refused;
    try std.testing.expect(std.mem.indexOf(u8, denied, "mirror2.example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, denied, "nix.net.hosts") == null);
    try std.testing.expectEqualStrings(
        "nix.net.build.com.example.mirror2.443",
        refusing.action.read(),
    );
    try std.testing.expectEqual(@as(usize, 1), refusing.asks);
}

test "a nix host is read under two names, most specific first" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const table = try chock_policy.table.Table.parse(
        arena,
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "nix.net.com.example.wide.443", .decision = .allow },
        \\            .{ .action = "nix.net.com.example.both.443", .decision = .allow },
        \\            .{ .action = "nix.net.build.com.example.both.443", .decision = .deny },
        \\            .{ .action = "nix.net.com.example.asked.443", .decision = .allow },
        \\            .{ .action = "nix.net.build.com.example.asked.443", .decision = .ask },
        \\            .{ .action = "nix.net.com.example.narrow.443", .decision = .deny },
        \\            .{ .action = "nix.net.build.com.example.narrow.443", .decision = .allow },
        \\            .{ .action = "nix.net.eval.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ,
        null,
    );

    const rule = NixFetchGate.Rule{
        .policy = table,
        .chain = &.{"main"},
        .agent_kind = "main",
        .model = "test-model",
    };
    var building = NixFetchGate{
        .gpa = gpa,
        .io = std.testing.io,
        .asker = null,
        .installable = "/work#packages.x86_64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
        .rule = rule,
    };
    var evaluating = building;
    evaluating.kind = .flake_input;

    const wide = chock_nix.fetch.Fetch{
        .subject = "a.drv",
        .url = "https://wide.example.com/a",
        .host = "wide.example.com",
        .port = 443,
    };
    const both = chock_nix.fetch.Fetch{
        .subject = "b.drv",
        .url = "https://both.example.com/a",
        .host = "both.example.com",
        .port = 443,
    };
    const unnamed = chock_nix.fetch.Fetch{
        .subject = "c.drv",
        .url = "https://other.example.com/a",
        .host = "other.example.com",
        .port = 443,
    };

    try std.testing.expectEqual(
        chock_nix.fetch.RuleAnswer.allow,
        building.gate().ruleFor(wide),
    );
    try std.testing.expectEqual(
        chock_nix.fetch.RuleAnswer.allow,
        evaluating.gate().ruleFor(wide),
    );

    try std.testing.expectEqual(
        chock_nix.fetch.RuleAnswer.deny,
        building.gate().ruleFor(both),
    );
    try std.testing.expectEqual(
        chock_nix.fetch.RuleAnswer.allow,
        evaluating.gate().ruleFor(both),
    );

    try std.testing.expectEqual(
        chock_nix.fetch.RuleAnswer.unsettled,
        building.gate().ruleFor(unnamed),
    );

    const reader = NixTableReader{
        .policy = table,
        .chain = &.{"main"},
        .agent_kind = "main",
        .model = "test-model",
        .tool = "nix_build",
    };
    var scoped: [chock_broker.network.max_action_bytes]u8 = undefined;
    var either: [chock_broker.network.max_action_bytes]u8 = undefined;

    const asked = chock_broker.network.nixActionsInto(
        &scoped,
        &either,
        .build,
        "asked.example.com",
        443,
    ).?;
    try std.testing.expectEqual(chock_policy.table.Decision.ask, reader.decide(asked));

    const narrow = chock_broker.network.nixActionsInto(
        &scoped,
        &either,
        .build,
        "narrow.example.com",
        443,
    ).?;
    try std.testing.expectEqual(chock_policy.table.Decision.allow, reader.decide(narrow));
    try std.testing.expectEqual(
        chock_nix.fetch.RuleAnswer.allow,
        building.gate().ruleFor(.{
            .subject = "d.drv",
            .url = "https://narrow.example.com/a",
            .host = "narrow.example.com",
            .port = 443,
        }),
    );

    const nobody = chock_broker.network.nixActionsInto(
        &scoped,
        &either,
        .build,
        "other.example.com",
        443,
    ).?;
    try std.testing.expectEqual(chock_policy.table.Decision.ask, reader.decide(nobody));

    const empty = try chock_policy.table.Table.parse(arena, ".{}", null);
    const shipped = empty.decideChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "test-model",
        .tool = "nix_build",
        .action = NixFetchGate.opaque_action,
    }, null);
    try std.testing.expect(shipped.named);
    try std.testing.expectEqual(chock_policy.table.Decision.allow, shipped.decision);
}

test "a phase free rule settles a host before the batch question, and never after it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const table = try chock_policy.table.Table.parse(
        arena,
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "nix.net.com.example.mirror0.443", .decision = .allow },
        \\        },
        \\    },
        \\}
    ,
        null,
    );

    var log = try PermittingLog.init(gpa);
    defer log.deinit(io);
    try log.arm(io);

    var arbitrator = CountingArbiter{ .permitted = true };
    var gate = NixFetchGate{
        .gpa = gpa,
        .io = io,
        .asker = arbitrator.asker(&log.locked),
        .installable = "/work#packages.x86_64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
        .rule = .{
            .policy = table,
            .chain = &.{"main"},
            .agent_kind = "main",
            .model = "test-model",
        },
    };

    try std.testing.expect(
        try gate.gate().permitAll(arena, try manyHosts(arena, 4)) == .permitted,
    );
    try std.testing.expectEqual(@as(usize, 2), arbitrator.asks);
    try std.testing.expect(std.mem.indexOf(u8, arbitrator.detail.read(), "mirror0") == null);
}

test "nix.net at deny stops an eval fetch, a build fetch, a mirror set and an opaque fetch" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const table = try chock_policy.table.Table.parse(
        arena,
        \\.{
        \\    .policy = .{
        \\        .rules = .{ .{ .action = "nix.net.*", .decision = .deny } },
        \\    },
        \\}
    ,
        null,
    );

    const rule = NixFetchGate.Rule{
        .policy = table,
        .chain = &.{"main"},
        .agent_kind = "main",
        .model = "test-model",
    };
    var building = NixFetchGate{
        .gpa = gpa,
        .io = std.testing.io,
        .asker = null,
        .installable = "/work#packages.x86_64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
        .rule = rule,
    };
    var evaluating = building;
    evaluating.kind = .flake_input;

    const one = chock_nix.fetch.Fetch{
        .subject = "a.drv",
        .url = "https://files.example.com/a",
        .host = "files.example.com",
        .port = 443,
    };
    try std.testing.expectEqual(
        chock_nix.fetch.RuleAnswer.deny,
        building.gate().ruleFor(one),
    );
    try std.testing.expectEqual(
        chock_nix.fetch.RuleAnswer.deny,
        evaluating.gate().ruleFor(one),
    );

    const mirrors = [_]chock_nix.fetch.Mirror{
        .{ .base = "https://ftpmirror.gnu.org/", .url = "https://ftpmirror.gnu.org/a", .target = null },
    };
    var buffer: [chock_broker.network.max_mirror_action_bytes]u8 = undefined;
    const site_action = chock_broker.network.mirrorActionInto(
        &buffer,
        "gnu",
        &chock_nix.fetch.mirrorSetHash(&mirrors),
    ).?;

    const covered = [_][]const u8{
        site_action,
        NixFetchGate.opaque_action,
        NixFetchGate.many_action,
    };
    for (covered) |action| {
        try std.testing.expectEqual(chock_policy.table.Decision.deny, table.evaluateKindAlone(.{
            .agent_kind = "main",
            .model = "test-model",
            .tool = "nix_build",
            .action = action,
        }));
    }
}

test "a question carries the part of Chock that asked it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var log = try PermittingLog.init(gpa);
    defer log.deinit(io);
    try log.arm(io);

    var arbitrator = CountingArbiter{ .permitted = true };
    var gate = NixFetchGate{
        .gpa = gpa,
        .io = io,
        .asker = arbitrator.asker(&log.locked),
        .installable = "/work#packages.x86_64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
    };

    _ = try gate.gate().permitAll(arena, &.{.{
        .subject = "a.drv",
        .url = "https://files.example.com/a",
        .host = "files.example.com",
        .port = 443,
    }});
    try std.testing.expectEqualStrings("a Nix build", arbitrator.source.read());

    _ = try gate.gate().permitOpaque(arena, &.{"a-zig-deps.drv"});
    try std.testing.expectEqualStrings("a Nix build", arbitrator.source.read());

    gate.kind = .flake_input;
    _ = try gate.gate().permitAll(arena, &.{.{
        .subject = "nixpkgs",
        .url = "https://api.github.com",
        .host = "api.github.com",
        .port = 443,
    }});
    try std.testing.expectEqualStrings("a Nix flake input", arbitrator.source.read());

    try std.testing.expectEqualStrings("the sandbox", chock_broker.network.request_source);
    try std.testing.expectEqualStrings("git", chock_broker.git_shim.request_source);
}

test "a git daemon host is named in the build namespace, with its own port" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var gate = NixFetchGate{
        .gpa = gpa,
        .io = std.testing.io,
        .asker = null,
        .installable = "/work#packages.x86_64-linux.default",
        .call = .{ .call_id = "call1", .tool = "nix_build", .arguments = "{}" },
    };

    const said = (try gate.gate().permitAll(arena, &.{.{
        .subject = "a-systemtap.drv",
        .url = "git://sourceware.org/git/systemtap.git",
        .host = "sourceware.org",
        .port = 9418,
    }})).refused;
    try std.testing.expect(
        std.mem.indexOf(u8, said, "nix.net.build.org.sourceware.9418") != null,
    );
}
