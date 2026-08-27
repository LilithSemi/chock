//! Runs one `chock_core.tools.Registry.dispatch` call against a real
//! `sandbox.Config`, and prints the result. `lib/chock-core/tools.zig`'s own
//! `dispatch` calls `Sandbox.spawn`, which calls `fork`, and `fork` only
//! carries the calling thread into the child: see `Sandbox.spawn`'s own doc
//! comment. The zig test runner that runs `test/core/tools.zig`'s own tests
//! is not a single threaded caller. This program is, the same "outer process
//! builds a config, then execs a probe" shape `test/sandbox/escape.zig` and
//! `test/workspace/escape.zig` both use, for the same reason: see
//! `test/sandbox/escape_probe.zig`'s own top comment.
//!
//! Nothing in this file, and nothing in `lib/chock-core/tools.zig`, touches
//! `std.Io`: see `tools.zig`'s own top comment for why. Every path comes in
//! through argv, already resolved by `test/core/tools.zig`, which does use
//! `std.Io` freely, safely, because it never calls `dispatch` (and so never
//! calls `Sandbox.spawn`) itself.
//!
//! Command line:
//!   tools-probe <tool> <call_id> <root> <cwd> <mounts-blob> <rules-blob>
//!               <sandbox-env-blob> <host-path> <arguments-json>
//!               <timeout-ms> <memory-dir> <store-paths> <cache-dir>
//!               <cancel-after-ms> <scratch-dir> <scratch-bytes>
//!               <workspace-dir> <workspace-floor-bytes>
//!
//! **The last eight are always present and any of them may be empty**, which
//! is how an optional value crosses a command line without making the
//! argument count ambiguous.
//!
//! `<timeout-ms>` empty means the real default,
//! `chock_core.tools.default_timeout_ns`, the one every production caller
//! gets. Given, a test can pin the timeout behaviour itself without making
//! the whole suite wait out the real default: see `dispatchTimed`'s own doc
//! comment.
//!
//! `<memory-dir>` empty means this session has no knowledgebase, so the two
//! memory tools have nowhere to work. Given, it is the host directory
//! `write_memory` writes into and `read_memory` reads from, and **it is
//! mounted for those two calls and for no other**: see
//! `lib/chock-core/tools.zig`.
//!
//! `<cache-dir>` empty means this session has no toolchain cache, so a
//! `run_command` call gets no `HOME` and no writable directory outside the
//! workspace. Given, it is the host directory the cache lives in, and **it is
//! mounted for a `run_command` call and for no other**: see
//! `lib/chock-core/cache.zig`.
//!
//! `<scratch-dir>` empty means this session has no scratchpad, so a
//! `run_command` call keeps whatever `TMPDIR` it was given and can start no
//! background task. Given, it is the host session directory the scratchpad
//! lives in, and **this probe waits for every background task it started
//! before it exits**: a task's own thread dies with its process, and the whole
//! point of the read only output file is that the harness wrote it. See
//! `chock_core.tasks.Table`.
//!
//! `<scratch-bytes>` empty means the real default,
//! `sandbox.Limits.scratch_bytes`, which is 256 MiB and is what every
//! production call gets. Given, it is the cap on the tmpfs `TMPDIR` names, and
//! it exists so a test can fill that area with a small write instead of a
//! quarter of a gibibyte one. **It is only a cap**: the area itself is mounted
//! by the production path either way, so a test that names a small number still
//! runs the mechanism a real session runs.
//!
//! `<workspace-dir>` empty means no free space floor at all, which is what
//! Chock did before the floor existed and what every test that says nothing
//! here wants. Given, it is the host directory the workspace writes into, and
//! its filesystem is read with one `statfs` before every writing tool call.
//!
//! `<workspace-floor-bytes>` empty means the real default,
//! `chock_core.tools.default_workspace_free_floor_bytes`. Given, it is how much
//! room that filesystem must still have, and a test names a number the machine
//! it runs on is certain to be under or certain to be over rather than a number
//! that depends on the disk.
//!
//! `<cancel-after-ms>` empty means nothing ever cancels the call, which is
//! what every test but one wants. Given, this probe arms a repeating interval
//! timer at that period whose handler calls
//! `chock_core.tools.cancelRunningTool`, which is what `src/interrupt.zig`
//! does on a second Ctrl-C: see `armCancelTimer`.
//!
//! `<store-paths>` empty means the default of
//! `chock_core.tools.Context.store_paths`, the whole Nix store, which is
//! what a session with no dev shell gets and what every test that says
//! nothing here wants. Given, it is one host path per line, and it is the
//! **whole** toolchain the tool call gets: a session that names a narrow set
//! reaches nothing else. See `Context.store_paths`.
//!
//! `<mounts-blob>` and `<rules-blob>` are the same shape
//! `test/sandbox/escape.zig`'s own `serializeMounts` and `serializeRules`
//! build, documented in full at `test/sandbox/escape_probe.zig`'s own top
//! comment. `<sandbox-env-blob>` is one "KEY=VALUE" line per entry of the
//! `sandbox.Config.env` a real `Workspace.sandboxConfig` built (the git
//! variables for the worktree kind, empty for the overlay kind).
//! `<host-path>` is the one value `dispatch` ever reads off the host's own
//! environment: the `PATH` it resolves `argv[0]` against, before the sandbox
//! is ever built. `<arguments-json>` is the tool call's own JSON arguments,
//! exactly as the model would have sent them.
//!
//! Standard output, on success (exit 0), is one header line:
//!
//!   is_error=<0 or 1> truncated=<0 or 1> len=<decimal>
//!
//! followed by exactly `len` raw bytes: `ToolResult.output`, unmodified,
//! which may itself hold newlines. `test/core/tools.zig` reads the header
//! line first and then exactly `len` bytes, never splits on a newline
//! inside the body.
//!
//! Exit codes:
//!   0 - dispatch returned a result, printed above. is_error in the header
//!       carries whether the tool call itself was reported as failing: this
//!       exit code only means the probe itself did not fault.
//!   1 - the argument count on the command line is wrong.
//!   2 - a mounts or rules blob could not be parsed.
//!   3 - dispatch itself returned a real error (a sandbox or setup fault,
//!       not a tool level failure). The error name is on standard error.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("chock-sandbox");
const chock_core = @import("chock-core");

/// One half of `struct itimerval`, which `setitimer` takes and which is
/// microseconds, not nanoseconds. Written out here rather than taken from
/// `std.os.linux`, whose own `setitimer` wrapper names `itimerspec`: that is
/// the type `timer_settime` takes, and handing it to this syscall would read
/// a nanosecond field as a microsecond one.
const TimerValue = extern struct { sec: isize, usec: isize };

/// `struct itimerval`. `interval` is what makes the timer repeat.
const IntervalTimer = extern struct { interval: TimerValue, value: TimerValue };

/// End the tool call this process is running, from inside a signal handler,
/// which is the one place `src/interrupt.zig` ever calls this from.
fn onCancelAlarm(_: std.posix.SIG) callconv(.c) void {
    chock_core.tools.cancelRunningTool();
}

/// Call `chock_core.tools.cancelRunningTool` every `period_ms`, from a signal
/// handler, so a test can pin what a second Ctrl-C does to a call that is
/// already running.
///
/// **The timer repeats, and that is what keeps this from being a race.** A
/// single shot that landed before `Sandbox.spawn` had reported the call's own
/// process group would find nothing registered yet and cancel nothing, and
/// the call would then run to its own timeout instead: a different outcome
/// for a reason that has nothing to do with what is being pinned. A repeating
/// timer only has to land once after the call starts, and it goes on trying
/// until it does.
///
/// `SA_RESTART`, unlike `src/interrupt.zig`'s own handler, which deliberately
/// does without it: there the point is that a waiting read notices the signal,
/// and here the point is the opposite. The read loop in
/// `lib/chock-core/tools.zig` is the thing under test, and a shot that landed
/// while it waited must not change how it behaves.
fn armCancelTimer(period_ms: u64) void {
    const action = std.posix.Sigaction{
        .handler = .{ .handler = onCancelAlarm },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.ALRM, &action, null);

    const period: TimerValue = .{
        .sec = @intCast(period_ms / std.time.ms_per_s),
        .usec = @intCast((period_ms % std.time.ms_per_s) * std.time.us_per_ms),
    };
    const timer: IntervalTimer = .{ .interval = period, .value = period };
    const rc = linux.syscall3(.setitimer, @intFromEnum(linux.ITIMER.REAL), @intFromPtr(&timer), 0);
    if (linux.errno(rc) != .SUCCESS) std.debug.print("could not arm the cancel timer\n", .{});
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.args.toSlice(arena);
    if (args.len != 19) {
        std.debug.print(
            "usage: tools-probe <tool> <call_id> <root> <cwd> <mounts-blob> <rules-blob> " ++
                "<sandbox-env-blob> <host-path> <arguments-json> <timeout-ms> <memory-dir> " ++
                "<store-paths> <cache-dir> <cancel-after-ms> <scratch-dir> <scratch-bytes> " ++
                "<workspace-dir> <workspace-floor-bytes>\n",
            .{},
        );
        return 1;
    }
    const tool = args[1];
    const call_id = args[2];
    const root = args[3];
    const cwd = args[4];
    const mounts_blob = args[5];
    const rules_blob = args[6];
    const sandbox_env_blob = args[7];
    const host_path = args[8];
    const arguments_json = args[9];
    const timeout_ms: ?u64 = if (args[10].len != 0)
        std.fmt.parseInt(u64, args[10], 10) catch {
            std.debug.print("timeout-ms did not parse as an integer\n", .{});
            return 1;
        }
    else
        null;
    const memory_dir: ?[]const u8 = if (args[11].len != 0) args[11] else null;
    const store_paths = parseLines(arena, args[12]) catch {
        std.debug.print("parsing the store paths blob failed\n", .{});
        return 2;
    };
    const cache_dir: ?[]const u8 = if (args[13].len != 0) args[13] else null;
    const scratch_dir: ?[]const u8 = if (args[15].len != 0) args[15] else null;
    const scratch_bytes: ?u64 = if (args[16].len != 0)
        std.fmt.parseInt(u64, args[16], 10) catch {
            std.debug.print("scratch-bytes did not parse as an integer\n", .{});
            return 1;
        }
    else
        null;
    const workspace_dir: ?[]const u8 = if (args[17].len != 0) args[17] else null;
    const workspace_floor_bytes: ?u64 = if (args[18].len != 0)
        std.fmt.parseInt(u64, args[18], 10) catch {
            std.debug.print("workspace-floor-bytes did not parse as an integer\n", .{});
            return 1;
        }
    else
        null;
    if (args[14].len != 0) {
        const cancel_after_ms = std.fmt.parseInt(u64, args[14], 10) catch {
            std.debug.print("cancel-after-ms did not parse as an integer\n", .{});
            return 1;
        };
        armCancelTimer(cancel_after_ms);
    }

    const mounts = parseMounts(arena, mounts_blob) catch {
        std.debug.print("parsing the mounts blob failed\n", .{});
        return 2;
    };
    const rules = parseRules(arena, rules_blob) catch {
        std.debug.print("parsing the rules blob failed\n", .{});
        return 2;
    };
    const sandbox_env = parseEnvBlob(arena, sandbox_env_blob) catch {
        std.debug.print("parsing the sandbox env blob failed\n", .{});
        return 2;
    };

    var env = std.process.Environ.Map.init(arena);
    env.put("PATH", host_path) catch return error.OutOfMemory;

    var config = sandbox.Config{
        .root = root,
        .mounts = mounts,
        .rules = rules,
        .cwd = cwd,
        .env = sandbox_env,
    };
    // The cap on the tmpfs `TMPDIR` names, and nothing else about the limits:
    // every other number stays the production default, so a test that fills a
    // small area still runs against the memory ceiling, the process count and
    // the descriptor count a real call gets.
    if (scratch_bytes) |bytes| config.limits.scratch_bytes = bytes;

    const call = chock_core.tools.ToolCall{ .call_id = call_id, .tool = tool, .arguments = arguments_json };

    // An `Io` that cannot start a thread and cannot allocate. `Threaded.init`
    // uses its allocator only for `async`, `concurrent`, and the group calls,
    // so a failing allocator gives an `Io` that still reads a clock and can do
    // nothing that takes a lock this process would carry into a fork. That is
    // what makes it safe here, in the one process that calls `Sandbox.spawn`
    // and then becomes the child.
    var threaded = std.Io.Threaded.init(std.mem.Allocator.failing, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // `dispatchWith` with the default timeout is exactly what `dispatch`
    // does, so a probe run with an empty `<timeout-ms>` still goes down the
    // production path and not a test only one.
    // A `Context` whose `store_paths` is left at its own default when the
    // command line named none, so a probe run that says nothing about the
    // toolchain takes exactly the production default and not a test only
    // value of this file's own.
    var context = chock_core.tools.Context{
        .timeout_ns = if (timeout_ms) |ms| ms * std.time.ns_per_ms else chock_core.tools.default_timeout_ns,
        .memory_dir = memory_dir,
        .cache_dir = cache_dir,
        .scratch_dir = scratch_dir,
        .workspace_dir = workspace_dir,
        .session_id = "probe-session",
    };
    if (store_paths.len != 0) context.store_paths = store_paths;
    if (workspace_floor_bytes) |bytes| context.workspace_free_floor_bytes = bytes;

    // The session's own task table, when the command line named a scratchpad.
    // The page allocator, never the arena, for the reason
    // `chock_core.tasks.Table.gpa` gives: a task's own thread allocates from
    // it beside a thread that may be inside `Sandbox.spawn`.
    var tasks_dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var table: ?chock_core.tasks.Table = if (scratch_dir) |dir| .{
        .gpa = std.heap.page_allocator,
        .dir = std.fmt.bufPrint(&tasks_dir_buffer, "{s}/{s}", .{ dir, chock_core.tasks.host_leaf }) catch {
            std.debug.print("the scratchpad path is too long\n", .{});
            return 1;
        },
        .runner = chock_core.tools.backgroundRunner(),
    } else null;
    if (table) |*one| context.tasks = one;

    const result = chock_core.tools.Registry.dispatchWith(arena, io, &env, config, call, context) catch |err| {
        std.debug.print("dispatch failed: {s}\n", .{@errorName(err)});
        return 3;
    };

    // Before the result is printed and before this process ends: a background
    // task's thread dies with its process, and the file it writes is the whole
    // point. `test/core/tools.zig` reads that file on the host afterwards.
    if (table) |*one| one.deinit();

    printResult(result);
    return 0;
}

/// Write the header line and the raw body, documented at this file's own
/// top comment, to standard output. A raw `linux.write` loop, not
/// `std.debug.print`: the body can hold arbitrary bytes, including ones
/// `std.debug.print`'s own formatting is not meant to carry through intact,
/// and a header built with `std.fmt.bufPrint` keeps this the same "no
/// hidden allocation on the standard output path" shape every other probe
/// in this project uses.
fn printResult(result: chock_core.tools.ToolResult) void {
    var header_buffer: [128]u8 = undefined;
    const header = std.fmt.bufPrint(
        &header_buffer,
        "is_error={d} truncated={d} len={d}\n",
        .{ @intFromBool(result.is_error), @intFromBool(result.truncated), result.output.len },
    ) catch unreachable;
    writeAll(header);
    writeAll(result.output);
}

fn writeAll(bytes: []const u8) void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = linux.write(std.posix.STDOUT_FILENO, bytes.ptr + offset, bytes.len - offset);
        const write_errno = linux.errno(n);
        if (write_errno == .INTR) continue;
        if (write_errno != .SUCCESS) return;
        offset += @intCast(n);
    }
}

const ParseError = error{ OutOfMemory, BadBlob };

/// Same shape as `test/sandbox/escape_probe.zig`'s own `parseMounts`: one
/// line per mount, fields separated by 0x01, the first field always the
/// kind.
fn parseMounts(arena: std.mem.Allocator, blob: []const u8) ParseError![]sandbox.namespace.Mount {
    var list: std.ArrayList(sandbox.namespace.Mount) = .empty;
    if (blob.len == 0) return list.toOwnedSlice(arena) catch return error.OutOfMemory;

    var lines = std.mem.splitScalar(u8, blob, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, 0x01);
        const kind = fields.next() orelse return error.BadBlob;
        if (std.mem.eql(u8, kind, "bind")) {
            const source = fields.next() orelse return error.BadBlob;
            const target = fields.next() orelse return error.BadBlob;
            const read_only_field = fields.next() orelse return error.BadBlob;
            try list.append(arena, .{ .bind = .{
                .source = source,
                .target = target,
                .read_only = std.mem.eql(u8, read_only_field, "1"),
            } });
        } else if (std.mem.eql(u8, kind, "overlay")) {
            const lower = fields.next() orelse return error.BadBlob;
            const upper = fields.next() orelse return error.BadBlob;
            const work = fields.next() orelse return error.BadBlob;
            const target = fields.next() orelse return error.BadBlob;
            try list.append(arena, .{ .overlay = .{
                .lower = lower,
                .upper = upper,
                .work = work,
                .target = target,
            } });
        } else if (std.mem.eql(u8, kind, "proc")) {
            const target = fields.next() orelse return error.BadBlob;
            try list.append(arena, .{ .proc = .{ .target = target } });
        } else {
            return error.BadBlob;
        }
    }
    return list.toOwnedSlice(arena) catch return error.OutOfMemory;
}

/// Same shape as `test/sandbox/escape_probe.zig`'s own `parseRules`.
fn parseRules(arena: std.mem.Allocator, blob: []const u8) ParseError![]sandbox.Config.Rule {
    var list: std.ArrayList(sandbox.Config.Rule) = .empty;
    if (blob.len == 0) return list.toOwnedSlice(arena) catch return error.OutOfMemory;

    var lines = std.mem.splitScalar(u8, blob, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, 0x01);
        const path = fields.next() orelse return error.BadBlob;
        const bits_field = fields.next() orelse return error.BadBlob;
        const bits = std.fmt.parseInt(u64, bits_field, 10) catch return error.BadBlob;
        try list.append(arena, .{ .path = path, .access = @bitCast(bits) });
    }
    return list.toOwnedSlice(arena) catch return error.OutOfMemory;
}

/// One "KEY=VALUE" string per line, already complete, no field separator
/// needed: the same shape `test/sandbox/escape_probe.zig`'s own
/// `parseEnvBlob` reads.
/// One path per line, empty lines dropped. `<store-paths>` uses this, and
/// so does `<sandbox-env-blob>` through `parseEnvBlob` below, which is the
/// same shape with a different meaning per line.
fn parseLines(arena: std.mem.Allocator, blob: []const u8) ParseError![][]const u8 {
    return parseEnvBlob(arena, blob);
}

fn parseEnvBlob(arena: std.mem.Allocator, blob: []const u8) ParseError![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    if (blob.len == 0) return list.toOwnedSlice(arena) catch return error.OutOfMemory;

    var lines = std.mem.splitScalar(u8, blob, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try list.append(arena, line);
    }
    return list.toOwnedSlice(arena) catch return error.OutOfMemory;
}
