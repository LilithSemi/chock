//! Runs one `chock_core.tools.Registry.dispatch` call against a real
//! `sandbox.Config` and prints the result. Its own process because `dispatch`
//! calls `fork`, which carries only the calling thread into the child, and the
//! zig test runner is not a single threaded caller. Nothing here touches
//! `std.Io`: every path arrives through argv.
//!
//! Command line:
//!   tools-probe <tool> <call_id> <root> <cwd> <mounts-blob> <rules-blob>
//!               <sandbox-env-blob> <host-path> <arguments-json>
//!               <timeout-ms> <memory-dir> <store-paths> <cache-dir>
//!               <cancel-after-ms> <scratch-dir> <scratch-bytes>
//!               <workspace-dir> <workspace-floor-bytes>
//!               <approval-wait-ms> <routed>
//!
//! Every optional argument is always present and may be empty, so the argument
//! count never goes ambiguous. Empty means the production default. The blob
//! arguments take the shape `test/sandbox/escape_probe.zig` documents.
//!
//! Standard output, on exit 0, is one header line:
//!
//!   is_error=<0 or 1> truncated=<0 or 1> len=<decimal> note_len=<decimal>
//!     media_len=<decimal> image_bytes=<decimal> hash_len=<decimal>
//!     data_len=<decimal>
//!
//! then that many raw bytes, in that order: `ToolResult.output`,
//! `ToolResult.note`, then the three strings of `ToolResult.image`. Any of them
//! can hold a newline. `image_bytes` is the picture size before base64.
//!
//! Exit status:
//!   0   dispatch returned a result, printed above. `is_error` in the header
//!       says whether the tool call itself was reported as failing
//!   1   the argument count on the command line is wrong
//!   2   a mounts or rules blob did not parse
//!   3   dispatch returned a real error, named on standard error
//!  63   this machine would not give the sandbox its namespaces, so the call
//!       never ran. Not a pass and not a failure: the caller skips

const std = @import("std");

const linux = std.os.linux;
const sandbox = @import("chock-sandbox");
const chock_core = @import("chock-core");

/// Half of `struct itimerval`, in microseconds. `std.os.linux`'s `setitimer`
/// wrapper names `itimerspec`, whose nanosecond field this syscall would read
/// as a microsecond one.
const TimerValue = extern struct { sec: isize, usec: isize };

const IntervalTimer = extern struct { interval: TimerValue, value: TimerValue };

fn onCancelAlarm(_: std.posix.SIG) callconv(.c) void {
    chock_core.tools.cancelRunningTool();
}

/// The timer repeats: a single shot landing before `Sandbox.spawn` reported the
/// process group would cancel nothing. `SA_RESTART`, so the read loop under
/// test does not see a short read.
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
    if (args.len != 21) {
        std.debug.print(
            "usage: tools-probe <tool> <call_id> <root> <cwd> <mounts-blob> <rules-blob> " ++
                "<sandbox-env-blob> <host-path> <arguments-json> <timeout-ms> <memory-dir> " ++
                "<store-paths> <cache-dir> <cancel-after-ms> <scratch-dir> <scratch-bytes> " ++
                "<workspace-dir> <workspace-floor-bytes> <approval-wait-ms> <routed>\n",
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
    const approval_wait_ms: ?u64 = if (args[19].len != 0)
        std.fmt.parseInt(u64, args[19], 10) catch {
            std.debug.print("approval-wait-ms did not parse as an integer\n", .{});
            return 1;
        }
    else
        null;
    // Any router makes the call a routed one, which writes the resolver files.
    const routed = args[20].len != 0;

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
    // Only the tmpfs cap. Every other limit stays the production default.
    if (scratch_bytes) |bytes| config.limits.scratch_bytes = bytes;

    const call = chock_core.tools.ToolCall{ .call_id = call_id, .tool = tool, .arguments = arguments_json };

    // `Threaded.init` uses its allocator only for `async`, `concurrent` and the
    // group calls, so a failing allocator takes no lock a fork would carry.
    var threaded = std.Io.Threaded.init(std.mem.Allocator.failing, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var approval_wait_counter: std.atomic.Value(u64) = .init(0);

    var context = chock_core.tools.Context{
        .timeout_ns = if (timeout_ms) |ms| ms * std.time.ns_per_ms else chock_core.tools.default_timeout_ns,
        .memory_dir = memory_dir,
        .cache_dir = cache_dir,
        .scratch_dir = scratch_dir,
        .workspace_dir = workspace_dir,
        .session_id = "probe-session",
    };
    if (routed) context.net = refusing_seam.seam();
    if (store_paths.len != 0) context.store_paths = store_paths;
    if (workspace_floor_bytes) |bytes| context.workspace_free_floor_bytes = bytes;
    if (approval_wait_ms) |ms| {
        approval_wait_counter = .init(ms * std.time.ns_per_ms);
        context.approval_wait_ns = &approval_wait_counter;
    }

    // The page allocator, never the arena: a task's thread allocates beside one
    // that may be inside `Sandbox.spawn`.
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

    const result = chock_core.tools.Registry.dispatchWith(arena, io, &env, config, call, context) catch |err| switch (err) {
        // Nothing is printed here: `build.zig`'s `failOnTestStderr` fails the
        // build on a byte written to standard error.
        error.NamespaceFailed => return sandbox.namespace.nothing_measured_exit_status,
        else => {
            std.debug.print("dispatch failed: {s}\n", .{@errorName(err)});
            return 3;
        },
    };

    // A background task's thread dies with its process, and the file it writes
    // is what the caller reads.
    if (table) |*one| one.deinit();

    printResult(result);
    return 0;
}

/// A raw write loop: the body holds arbitrary bytes and must not allocate.
fn printResult(result: chock_core.tools.ToolResult) void {
    const image = result.image orelse chock_core.tools.ImageRef{
        .media_type = "",
        .byte_count = 0,
        .content_hash = "",
        .data = "",
    };
    var header_buffer: [256]u8 = undefined;
    const header = std.fmt.bufPrint(
        &header_buffer,
        "is_error={d} truncated={d} len={d} note_len={d} " ++
            "media_len={d} image_bytes={d} hash_len={d} data_len={d}\n",
        .{
            @intFromBool(result.is_error),
            @intFromBool(result.truncated),
            result.output.len,
            result.note.len,
            image.media_type.len,
            image.byte_count,
            image.content_hash.len,
            image.data.len,
        },
    ) catch unreachable;
    writeAll(header);
    writeAll(result.output);
    writeAll(result.note);
    writeAll(image.media_type);
    writeAll(image.content_hash);
    writeAll(image.data);
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

/// One line per mount, fields separated by 0x01, the first field the kind.
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

/// One complete string per line, empty lines dropped.
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

/// Refuses everything, so a test using it proves only what a routed call places
/// for the program, and nothing about resolving a name or reaching a host.
var refusing_seam: RefusingNetwork = .{};

const RefusingNetwork = struct {
    fn seam(self: *RefusingNetwork) chock_core.tools.NetSeam {
        return .{ .ptr = self, .vtable = &seam_vtable };
    }

    const seam_vtable = chock_core.tools.NetSeam.VTable{
        .router = routerFn,
        .background_router = backgroundRouterFn,
    };

    fn routerFn(ptr: *anyopaque, _: []const u8, _: []const u8) sandbox.NetRouter {
        return .{ .ptr = ptr, .vtable = &router_vtable };
    }

    fn backgroundRouterFn(ptr: *anyopaque, _: []const u8, _: []const u8) ?sandbox.NetRouter {
        return .{ .ptr = ptr, .vtable = &router_vtable };
    }

    const router_vtable = sandbox.NetRouter.VTable{ .resolve = resolveFn, .open = openFn };

    fn resolveFn(_: *anyopaque, _: []const u8, _: sandbox.NetRouter.Family) sandbox.NetRouter.Resolution {
        return .refused;
    }

    fn openFn(_: *anyopaque, _: sandbox.NetRouter.Address, _: u16) sandbox.NetBroker.Grant {
        return .refused;
    }
};
