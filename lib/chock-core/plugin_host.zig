//! The plugin host process, and the pipe that reaches it.
//!
//! `lib/chock-core/plugin.zig` decides which tools are offered.
//! `lib/chock-core/plugin_engine.zig` is what runs one, inside the host
//! process. **This file is the boundary between them**, and the boundary is a
//! process, not a function call.
//!
//! ## Why a process, and why it is locked down and not trusted
//!
//! **WebAssembly buys this host nothing.** Measured on Vulcan 2026-08-22:
//! `memPtr` is `mem_base + addr + offset` with **no bounds check**, and
//! `callIndirect` loads a table slot and calls it with **neither a bounds
//! check nor a signature check**. A module declaring sixteen pages and storing
//! to offset 100000000 **dumped core**, where wasmtime trapped.
//!
//! So a running guest owns the whole address space of the process that runs
//! it. Every consequence follows from that one fact:
//!
//! * **The plugin host is a sandboxed process, locked down like the agent
//!   sandbox and not like a helper.** `lockdown` below builds its config from
//!   the config a tool call gets, and takes things away rather than adding
//!   them. **Do not relax it on the grounds that a wasm guest is contained.**
//! * **One plugin, one process.** A guest that dumps core takes down its own
//!   host and nothing else, and the harness reads that as the channel ending.
//! * **The harness never believes anything about a plugin that it learned
//!   from the plugin's own process.** The tool list, the capability
//!   declarations and the policy decisions are all read out of the module's
//!   file by `plugin_module.read`, before any process starts. The only thing
//!   that comes back over this pipe is the text of one answer.
//! * **The capability gate runs before instantiation, in the host process, on
//!   a list that arrived on argv.** See `plugin_engine.gate`. argv is fixed
//!   before the process exists, so nothing on this wire can widen it.
//!
//! ## The framing is one line of JSON, the same as MCP and not the same as LSP
//!
//! A language server writes `Content-Length` headers. This does not, and
//! neither does an MCP server: one message is one line, and a message holds no
//! raw newline. The reasoning is `lib/chock-core/mcp_driver.zig`'s own and it
//! carries over whole, including why a partial line is never read as a whole
//! one.
//!
//! **Both sides of this wire are in this file**, which is the difference from
//! MCP worth stating. An MCP server is written by somebody else, so the risk
//! there is testing against a stand-in. Here the peer is a program this
//! project ships, so the two halves are read together and
//! `test/plugin/engine.zig` runs the real one.
//!
//! ## A plugin that crashes or hangs does not wedge the session
//!
//! * **Crashes.** The process exits, its end closes, and the next read answers
//!   end of file at once. `helper.Channel` turns that into `HelperGone`, which
//!   this file turns into `plugin.Error.Gone`, which `plugin.Session.dispatch`
//!   turns into one sentence the model reads.
//! * **Hangs.** Every exchange carries a deadline and `helper.Channel` answers
//!   `Late` rather than waiting. A guest inside an endless loop never gets to
//!   hold the session: the tool call answers, the turn goes on, and the next
//!   call still reaches the plugin because nothing was lost.
//! * **A plugin is not restarted.** `helper.Helper`'s own rule, for its own
//!   reason: a restart on every call does not converge.

const std = @import("std");
const builtin = @import("builtin");

const sandbox = @import("chock-sandbox");

const helper = @import("helper.zig");
const plugin = @import("plugin.zig");
const plugin_engine = @import("plugin_engine.zig");

/// The word on `chock`'s own command line that makes the process a plugin
/// host and not an agent session:
///
/// ```text
/// chock __plugin-host <module path> [capability ...]
/// ```
///
/// ## One binary, and a plugin still gets a process of its own
///
/// Chock links no libc and Zig cross compiles it, so an install is one file.
/// **A second program found beside the first is what breaks that.** The plugin
/// host was such a program: it was looked for in the directory `chock` itself
/// is in, so any install that moved one file and not the other lost every
/// plugin and said so in a warning nobody reads.
///
/// So `chock` re-execs itself instead, which is what
/// `chock_core.subagent.commandLine` already does for every subagent. Only the
/// count of artifacts changes: the plugin still runs in its own process, with
/// its own address space, inside the sandbox `lockdown` builds. **Do not read
/// this as a step toward running a guest inside the harness.** The whole of
/// this file's top comment argues against that.
///
/// ## Why the word is this shape
///
/// It is **not** in `src/main.zig`'s command table, so `chock --help` cannot
/// list it and `chock <a word that is not a command>` cannot reach it. The
/// leading underscores are what keep it away from a typing slip: no word the
/// program answers to is within two edits of it, which `src/main.zig` pins by
/// measuring the distance rather than by asserting it.
pub const verb = "__plugin-host";

/// The absolute path of the program that is running, which is the program a
/// plugin host process is started from.
///
/// **`/proc/self/exe` first, and `exe_path` after it.** `exe_path` is `argv[0]`,
/// which is a bare name for a person who ran `chock` off their `PATH`, and a
/// bare name is not a path anything can be mounted from. `/proc/self/exe`
/// answers for the running program whatever the caller was typed as, and it is
/// what a plugin needs on Linux, where a plugin host process is the only kind
/// there is.
///
/// **The answer is absolute or there is no answer**, and this is asserted here
/// rather than left to the caller. The path is bound into a mount tree, and
/// `chock_sandbox.namespace` takes an absolute path or nothing: a relative
/// source is an assertion failure of the whole session rather than one plugin
/// that did not load.
///
/// Null when neither candidate resolves. On Linux `/proc/self/exe` always
/// does, so a null there means `/proc` is not mounted, which is a machine that
/// cannot run a sandbox either.
pub fn selfProgramPath(
    keep: std.mem.Allocator,
    io: std.Io,
    exe_path: []const u8,
) std.mem.Allocator.Error!?[]const u8 {
    for ([_][]const u8{ "/proc/self/exe", exe_path }) |candidate| {
        if (candidate.len == 0) continue;
        const resolved = std.Io.Dir.cwd().realPathFileAlloc(io, candidate, keep) catch continue;
        std.debug.assert(std.fs.path.isAbsolute(resolved));
        return resolved;
    }
    return null;
}

/// The most this driver holds of a message that has not finished arriving.
///
/// The sender is a program this project ships, so this is a bound against a
/// fault and not against malice, and it is above what any answer can be:
/// `chock_plugin_core.call.max_result_bytes` is one mebibyte and JSON escaping
/// can at most sextuple a byte.
pub const max_inbox_bytes = 8 << 20;

/// How much is read from the pipe in one go.
const read_chunk_bytes = 4096;

/// What one message on this wire is. The name goes in the `op` field, so a
/// message a side does not know is skipped by name rather than guessed at.
pub const Op = enum {
    /// Harness to host: run one tool.
    call,
    /// Host to harness: what the tool said.
    result,

    pub fn name(self: Op) []const u8 {
        return @tagName(self);
    }
};

/// One request, as it goes on the wire.
pub const Call = struct {
    op: []const u8 = "call",
    id: i64,
    /// The tool's position in the metadata's own list. See `plugin.Offer.index`.
    index: u32,
    /// The JSON text the model wrote.
    arguments: []const u8,
};

/// One reply, as it goes on the wire.
pub const Result = struct {
    op: []const u8 = "result",
    id: i64,
    /// True when the tool said the call failed, or when this host could not
    /// run it. **Both are results and neither ends the plugin**: a guest that
    /// refused and a guest whose answer could not be read are things the model
    /// reads and acts on.
    is_error: bool,
    text: []const u8,
};

/// The half of this file that speaks the wire over one `helper.Channel`.
///
/// **Separate from `Driver` so a test can drive it with no sandbox at all.** A
/// `helper.Channel` is two ordinary pipes, so the production framing, the
/// production JSON and the production reply walk all run on both platforms.
pub const Protocol = struct {
    /// The allocator `inbox` lives in. It outlives one exchange by definition.
    gpa: std.mem.Allocator,

    /// Bytes read from the host and not yet consumed. **It survives an
    /// exchange that ran out of budget**, which is the whole reason it is a
    /// field: the bytes are still in the pipe and the next ask consumes them.
    inbox: std.ArrayList(u8) = .empty,

    /// The id of the last request this harness sent.
    last_id: i64 = 0,

    pub fn deinit(self: *Protocol) void {
        self.inbox.deinit(self.gpa);
        self.* = undefined;
    }

    /// Run one tool and answer what it said.
    pub fn call(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        index: u32,
        arguments: []const u8,
    ) plugin.Error!plugin.Outcome {
        self.last_id += 1;
        const id = self.last_id;

        try self.send(arena, io, channel, deadline, Call{
            .id = id,
            .index = index,
            .arguments = arguments,
        });

        const reply = try self.awaitReply(arena, io, channel, deadline, id);
        const text = blk: {
            const raw = reply.get("text") orelse break :blk "";
            if (raw != .string) break :blk "";
            break :blk raw.string;
        };
        const failed = blk: {
            const raw = reply.get("is_error") orelse break :blk false;
            if (raw != .bool) break :blk false;
            break :blk raw.bool;
        };
        return .{ .text = text, .is_error = failed };
    }

    /// Write one message and the newline that ends it, in **one** `writeAll`.
    ///
    /// One call and not two, so a failure can never leave a message on the
    /// wire with no newline behind it, which would join it to the next one.
    /// `helper.Channel.writeAll` poisons the channel on a partial write for
    /// the same reason, one layer down.
    fn send(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        message: anytype,
    ) plugin.Error!void {
        _ = self;
        const body = try std.json.Stringify.valueAlloc(arena, message, .{});
        const framed = try std.fmt.allocPrint(arena, "{s}\n", .{body});
        channel.writeAll(io, framed, deadline) catch |err| return switch (err) {
            // A write that ran out of budget left half a message behind and
            // poisoned the channel, so the plugin is finished with even though
            // the reason was a clock. Never `Late`, which would say the
            // session can ask again.
            error.Late, error.HelperGone => error.Gone,
        };
    }

    /// Read messages until the one that answers `id` arrives.
    ///
    /// A reply must carry this id **and** be a result. A host that wrote
    /// anything else is walked past rather than believed, the rule
    /// `chock_core.mcp_driver.awaitReply` already keeps: a message that only
    /// matches on its id is not an answer.
    fn awaitReply(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        id: i64,
    ) plugin.Error!std.json.ObjectMap {
        while (true) {
            const message = try self.receive(arena, io, channel, deadline);
            if (message != .object) continue;
            const object = message.object;

            const op = object.get("op") orelse continue;
            if (op != .string or !std.mem.eql(u8, op.string, Op.result.name())) continue;
            const answered = object.get("id") orelse continue;
            if (answered != .integer or answered.integer != id) continue;
            return object;
        }
    }

    /// The next whole message from the host, parsed.
    fn receive(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) plugin.Error!std.json.Value {
        while (true) {
            if (try self.takeLine(arena)) |line| {
                if (line.len == 0) continue;
                // A line that is not JSON is skipped: the framing is the
                // newline, so nothing is out of step. The host process writes
                // only JSON, and a library it links could still write a line
                // to standard output.
                const parsed = std.json.parseFromSliceLeaky(
                    std.json.Value,
                    arena,
                    line,
                    .{},
                ) catch continue;
                return parsed;
            }

            var scratch: [read_chunk_bytes]u8 = undefined;
            const count = channel.read(io, &scratch, deadline) catch |err| return switch (err) {
                error.Late => error.Late,
                error.HelperGone => error.Gone,
            };
            if (self.inbox.items.len + count > max_inbox_bytes) {
                channel.poisoned = true;
                return error.Gone;
            }
            try self.inbox.appendSlice(self.gpa, scratch[0..count]);
        }
    }

    /// The first whole line in `inbox`, copied into `arena`, with that line and
    /// its newline removed. Null when no whole line has arrived.
    ///
    /// **Nothing is removed for a line that is only partly here.** A host that
    /// died mid sentence leaves an incomplete line that is never mistaken for a
    /// whole one.
    fn takeLine(self: *Protocol, arena: std.mem.Allocator) plugin.Error!?[]const u8 {
        const end = std.mem.indexOfScalar(u8, self.inbox.items, '\n') orelse return null;
        var body = self.inbox.items[0..end];
        if (body.len != 0 and body[body.len - 1] == '\r') body = body[0 .. body.len - 1];
        const line = try arena.dupe(u8, body);
        self.inbox.replaceRange(self.gpa, 0, end + 1, &.{}) catch unreachable;
        return line;
    }
};

/// One plugin host process, from the first call of a session to the last.
///
/// **Owned by the caller that owns the session**, beside the `helper.Helper`
/// it drives and the `plugin.Session` that reads it.
pub const Driver = struct {
    gpa: std.mem.Allocator,

    /// The process this driver speaks to. **Not owned**: the caller starts the
    /// session, ends the session, and owns everything that lasts as long.
    process: *helper.Helper,

    /// What to start, if it is not started yet. The sandbox in it is
    /// `lockdown`'s answer and never a tool call's own config.
    request: helper.Request,

    /// The wire state, which survives a call that ran out of budget.
    protocol: Protocol,

    /// Why the plugin is finished with, or null while it works. Static text.
    failure: ?[]const u8 = null,

    pub fn init(gpa: std.mem.Allocator, process: *helper.Helper, request: helper.Request) Driver {
        return .{
            .gpa = gpa,
            .process = process,
            .request = request,
            .protocol = .{ .gpa = gpa },
        };
    }

    pub fn deinit(self: *Driver) void {
        self.protocol.deinit();
        self.* = undefined;
    }

    pub fn host(self: *Driver) plugin.Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = plugin.Host.VTable{ .call = callFn };

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        index: u32,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) plugin.Error!plugin.Outcome {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        // The name is for the message a person reads and never for the wire:
        // the guest ABI takes a number, and a name on the wire would be a
        // second thing the two sides have to agree about.
        _ = name;
        const channel = try self.live(io);
        const deadline = helper.Channel.deadlineIn(io, budget_ns);
        return self.protocol.call(arena, io, channel, deadline, index, arguments) catch |err| {
            return self.note(err);
        };
    }

    /// Keep the first reason a plugin was finished with, and hand the error
    /// on. **The first and not the last**, the rule every diagnostic in this
    /// project follows.
    fn note(self: *Driver, err: plugin.Error) plugin.Error {
        if (err == error.Gone and self.failure == null) self.failure = plugin.start_failed;
        return err;
    }

    /// The channel, starting the host process if this is the first call.
    ///
    /// **Started on the first call and not at session start.** A project that
    /// names a plugin pays for the process when a tool of it is first used and
    /// not before, the same rule `chock_core.mcp_driver` and
    /// `chock_core.lsp_driver` keep. Reading the plugin's metadata already
    /// happened, with no process at all.
    fn live(self: *Driver, io: std.Io) plugin.Error!*helper.Channel {
        if (self.failure != null) return error.Gone;
        if (!self.process.started) {
            self.process.start(io, self.request) catch {
                self.failure = plugin.start_failed;
                return error.Gone;
            };
        }
        return self.process.live() orelse {
            if (self.failure == null) self.failure = plugin.start_failed;
            return error.Gone;
        };
    }
};

/// The other half of the wire: the loop the plugin host process runs.
///
/// **In this file and not in the program**, so the two sides of one wire are
/// read together and a change to the framing cannot land on one of them alone.
/// `src/plugin-host.zig` is the program, and it is only an engine, a module
/// and a call to this.
///
/// It reads one line at a time from `input` and writes one line at a time to
/// `output`, and it returns when `input` reaches end of file, which is what
/// the harness closing its end means.
///
/// `runner` is a `plugin_engine.Runner` that has already been through the gate
/// and instantiated, or `load_failure` says why it has not. **A host process
/// whose plugin would not load still serves**, and answers every call with the
/// reason: a process that exited instead would be read by the harness as a
/// crash, which is a different fact and a worse message.
pub fn serve(
    gpa: std.mem.Allocator,
    io: std.Io,
    input: std.Io.File,
    output: std.Io.File,
    runner: ?*plugin_engine.Runner,
    load_failure: ?[]const u8,
) !void {
    var inbox: std.ArrayList(u8) = .empty;
    defer inbox.deinit(gpa);

    while (true) {
        const end = std.mem.indexOfScalar(u8, inbox.items, '\n') orelse {
            var scratch: [read_chunk_bytes]u8 = undefined;
            var data: [1][]u8 = .{&scratch};
            const count = std.Io.File.readStreaming(input, io, &data) catch return;
            // End of file: the harness closed its end and the session is over.
            if (count == 0) return;
            if (inbox.items.len + count > max_inbox_bytes) return error.MessageTooLong;
            try inbox.appendSlice(gpa, scratch[0..count]);
            continue;
        };

        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const line = try arena.dupe(u8, inbox.items[0..end]);
        inbox.replaceRange(gpa, 0, end + 1, &.{}) catch unreachable;

        const request = parseCall(arena, line) orelse continue;
        const answer = runOne(arena, runner, load_failure, request);

        const body = try std.json.Stringify.valueAlloc(arena, Result{
            .id = request.id,
            .is_error = answer.is_error,
            .text = answer.text,
        }, .{});
        const framed = try std.fmt.allocPrint(arena, "{s}\n", .{body});
        // One write, so a failure never leaves a message with no newline
        // behind it. The harness's own `send` keeps the same rule.
        try std.Io.File.writeStreamingAll(output, io, framed);
    }
}

/// One call read off the wire, or null when the line is not one.
///
/// **A line this side cannot read is skipped and never answered.** The framing
/// is the newline, so nothing is out of step, and answering an id this side
/// invented would put a reply on the wire for a request the harness never
/// made.
fn parseCall(arena: std.mem.Allocator, line: []const u8) ?struct { id: i64, index: u32, arguments: []const u8 } {
    if (line.len == 0) return null;
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{}) catch return null;
    if (parsed != .object) return null;

    const op = parsed.object.get("op") orelse return null;
    if (op != .string or !std.mem.eql(u8, op.string, Op.call.name())) return null;

    const id = parsed.object.get("id") orelse return null;
    if (id != .integer) return null;

    const index = parsed.object.get("index") orelse return null;
    if (index != .integer or index.integer < 0 or index.integer > std.math.maxInt(u32)) return null;

    const arguments = blk: {
        const raw = parsed.object.get("arguments") orelse break :blk "";
        if (raw != .string) break :blk "";
        break :blk raw.string;
    };

    return .{ .id = id.integer, .index = @intCast(index.integer), .arguments = arguments };
}

/// Run one call, and turn every way it can go wrong into a result.
fn runOne(
    arena: std.mem.Allocator,
    runner: ?*plugin_engine.Runner,
    load_failure: ?[]const u8,
    request: anytype,
) plugin.Outcome {
    if (load_failure) |why| return .{ .text = why, .is_error = true };
    const live = runner orelse return .{
        .text = "this plugin has no engine in this build of Chock",
        .is_error = true,
    };

    const outcome = live.call(request.index, request.arguments) catch |err| return .{
        .text = std.fmt.allocPrint(arena, "the plugin could not run that tool: {t}", .{err}) catch
            "the plugin could not run that tool",
        .is_error = true,
    };
    // **Copied out of the guest's memory before it is written.** The text
    // points into a memory the guest owns and the next call would overwrite,
    // and JSON stringify reads it after this function has returned.
    return .{
        .text = arena.dupe(u8, outcome.text) catch "the answer could not be held",
        .is_error = outcome.is_error,
    };
}

/// The sandbox a plugin host process gets, built from the one a tool call
/// gets by **taking things away**.
///
/// A caller hands in the config it already built for a tool call, which is the
/// only way to be sure a plugin never reaches something a tool call cannot.
/// This function then narrows it, and every narrowing is here because a guest
/// owns this process:
///
/// * **No network, ever.** A tool call may be given a broker. A plugin is not,
///   and there is no argument that would give it one: a plugin declares its
///   capabilities in its metadata and no capability supplies a socket in this
///   build. See `plugin_engine.importsFor`.
/// * **Nothing writable.** Every rule the caller's config carries is dropped,
///   and the caller states instead the whole of what this process may reach in
///   `reach`. Every right in it that is not a read is taken off here, by
///   `readOnly`, so a caller cannot hand a writable path over by mistake. **A
///   plugin's whole effect on the machine is the text of its answer.**
///
/// ## Why `reach` is not empty, which it used to be
///
/// **A process with no Landlock rule cannot start.** The ruleset handles the
/// execute right for every path, so `execve` on the host program itself is
/// refused with `EACCES` before one instruction of it runs, and the module is
/// a file this process opens by name. Measured, and the same fact
/// `test/sandbox/probe.zig` records for its own probe binary.
///
/// So a caller names the plugin host program, with the execute right, and the
/// plugin's own module, and whatever the program needs to be loaded at all. See
/// `src/run.zig`'s own `pluginSandbox`, which is that caller and states each
/// one and why. **The workspace is not among them**, and neither is anything
/// the session writes.
///
/// **`stdin_fd`, `stdout_fd` and `stderr_fd` are left alone here**, because
/// `helper.Helper.start` overwrites all three.
///
/// The rules live in `allocator`, which must outlive the process.
pub fn lockdown(
    allocator: std.mem.Allocator,
    config: sandbox.Config,
    reach: []const sandbox.Config.Rule,
) std.mem.Allocator.Error!sandbox.Config {
    const rules = try allocator.alloc(sandbox.Config.Rule, reach.len);
    for (rules, reach) |*slot, one| slot.* = .{ .path = one.path, .access = readOnly(one.access) };

    var out = config;
    out.network = .none;
    out.rules = rules;
    return out;
}

/// The rights of `access` that read something, and none of the rights that
/// change something.
///
/// **The list is written the safe way round**: it names what survives rather
/// than what is dropped, so a right Landlock gains in a later ABI is refused
/// here until somebody decides it belongs, instead of reaching a plugin host
/// the day the kernel learns it.
pub fn readOnly(access: sandbox.landlock.AccessFs) sandbox.landlock.AccessFs {
    return .{
        .execute = access.execute,
        .read_file = access.read_file,
        .read_dir = access.read_dir,
    };
}

// No test here starts a sandbox, and none reads a clock to decide anything.
// Every test drives the production `Protocol` over two ordinary pipes and
// writes the real bytes the host process writes, so the framing and the JSON
// are the production ones.
//
// **What none of these can reach is agreement with the real host process.**
// `test/plugin/engine.zig` runs it, with a real module and a real engine, for
// exactly that reason.

const testing = std.testing;
const chock_io = @import("chock-io");

/// Two pipes and the four descriptors they are made of, so a test can play the
/// host process by hand. The same shape `chock_core.helper`'s own tests use.
const Pair = struct {
    channel: helper.Channel,
    host_reads: std.Io.File,
    host_writes: std.Io.File,

    fn open() !Pair {
        const driver = chock_io.default();
        const requests = try driver.pipeCloseOnExec();
        const replies = try driver.pipeCloseOnExec();
        return .{
            .channel = .{
                .to_helper = .{ .handle = requests.write_fd, .flags = .{ .nonblocking = false } },
                .from_helper = .{ .handle = replies.read_fd, .flags = .{ .nonblocking = false } },
            },
            .host_reads = .{ .handle = requests.read_fd, .flags = .{ .nonblocking = false } },
            .host_writes = .{ .handle = replies.write_fd, .flags = .{ .nonblocking = false } },
        };
    }

    /// Put bytes in the pipe as the host process would. A pipe holds what is
    /// written until it is read, so a whole conversation can be staged before
    /// the harness says anything and no thread is needed.
    fn hostSays(self: *Pair, io: std.Io, bytes: []const u8) !void {
        try std.Io.File.writeStreamingAll(self.host_writes, io, bytes);
    }

    fn harnessWrote(self: *Pair, io: std.Io, buffer: []u8) ![]const u8 {
        var data: [1][]u8 = .{buffer};
        const count = try std.Io.File.readStreaming(self.host_reads, io, &data);
        return buffer[0..count];
    }

    fn close(self: *Pair, io: std.Io) void {
        for ([_]std.Io.File{
            self.channel.to_helper,
            self.channel.from_helper,
            self.host_reads,
            self.host_writes,
        }) |file| {
            if (file.handle < 0) continue;
            std.Io.File.close(file, io);
        }
    }
};

/// A deadline far enough ahead that an exchange between two ends of one pipe
/// in one process reaches it only if something is genuinely stuck. Nothing
/// asserts how long anything took; this is a bound, not a measurement.
fn generousDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return helper.Channel.deadlineIn(io, 30 * std.time.ns_per_s);
}

test "one call goes out as a line, and the answer comes back" {
    // The floor: the wire carries a tool call and its answer, one message per
    // line, with no header of any kind.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.hostSays(io,
        \\{"op":"result","id":1,"is_error":false,"text":"Hello, world!"}
    ++ "\n");

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expectEqualStrings("Hello, world!", outcome.text);
    try testing.expect(!outcome.is_error);

    var buffer: [4096]u8 = undefined;
    const wrote = try pair.harnessWrote(io, &buffer);
    try testing.expect(std.mem.indexOf(u8, wrote, "Content-Length") == null);
    try testing.expect(std.mem.endsWith(u8, wrote, "\n"));
    try testing.expect(std.mem.indexOf(u8, wrote, "\"op\":\"call\"") != null);
    // The index and not the name: the guest ABI takes a number.
    try testing.expect(std.mem.indexOf(u8, wrote, "\"index\":0") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wrote, "\n"));
}

test "a message that is not a result is walked past, whatever id it carries" {
    // A host process that wrote anything else must not have it read as an
    // answer. The test is not on the id alone, the rule
    // `chock_core.mcp_driver` learned against a real server.
    //
    // Mutation check: drop the `op` check in `awaitReply` and this test reads
    // the first line as the answer and gets an empty text.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.hostSays(io, "\n");
    try pair.hostSays(io, "this is not JSON at all\n");
    try pair.hostSays(io,
        \\{"op":"progress","id":1,"text":"still working"}
    ++ "\n");
    // A result for an id nobody asked about.
    try pair.hostSays(io,
        \\{"op":"result","id":99,"is_error":false,"text":"somebody else"}
    ++ "\n");
    try pair.hostSays(io,
        \\{"op":"result","id":1,"is_error":false,"text":"the real one"}
    ++ "\n");

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expectEqualStrings("the real one", outcome.text);
}

test "a plugin that crashes answers at once and stays gone" {
    // The fault this whole design is written against. A guest owns the host
    // process's address space, so a plugin that dumps core is the ordinary
    // case and not the exotic one: the process exits, its end closes, and the
    // harness must answer rather than wait.
    //
    // Mutation check: answer `Late` on end of file and the session waits out a
    // budget for a reply nobody will ever send.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    // Half a message, then the process is gone: exactly what a core dump
    // partway through a write looks like from here.
    try pair.hostSays(io, "{\"op\":\"result\",\"id\":1,\"te");
    std.Io.File.close(pair.host_writes, io);
    pair.host_writes = .{ .handle = -1, .flags = .{ .nonblocking = false } };

    try testing.expectError(error.Gone, protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    ));
    // And it stays gone: the channel is poisoned, so nothing asks a dead
    // process again.
    try testing.expect(pair.channel.poisoned);
    try testing.expectError(error.Gone, protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    ));
}

test "a plugin that hangs is late, and the session goes on" {
    // A guest inside an endless loop must not hold the session. The exchange
    // answers `Late`, the channel is not poisoned because nothing was lost,
    // and the next call still reaches the plugin.
    //
    // The deadline is already in the past, so nothing here waits for a clock:
    // `operateTimeout` sees a passed deadline and answers at once.
    //
    // Mutation check: poison the channel on `Late` in `receive` and the second
    // half of this test answers `Gone`.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const past = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Late, protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        past,
        0,
        "{}",
    ));
    try testing.expect(!pair.channel.poisoned);

    // The guest finished after all. The reply to the first call is still in
    // the pipe, so a second call reads it and then its own.
    try pair.hostSays(io,
        \\{"op":"result","id":1,"is_error":false,"text":"late but here"}
    ++ "\n");
    try pair.hostSays(io,
        \\{"op":"result","id":2,"is_error":false,"text":"the second one"}
    ++ "\n");
    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expectEqualStrings("the second one", outcome.text);
}

test "a tool that failed is a result and never a fault of this host" {
    // A plugin that answered `errorResult` did run, and what it said is what
    // the model reads. Turning it into an error here would hide the plugin's
    // own words behind this host's, and the model would repeat the call.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.hostSays(io,
        \\{"op":"result","id":1,"is_error":true,"text":"no such file"}
    ++ "\n");

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expect(outcome.is_error);
    try testing.expectEqualStrings("no such file", outcome.text);
}

test "the model's arguments cross as a string and not as a parsed object" {
    // The guest gets the text whole: nothing lowers the model's arguments into
    // a tool's own argument type, and the SDK refuses to compile a tool that
    // declares one. So the text must arrive unchanged, or `ctx.arguments` is a
    // field a tool body can never trust.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.hostSays(io,
        \\{"op":"result","id":1,"is_error":false,"text":"ok"}
    ++ "\n");
    _ = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        3,
        "{\"path\":\"a\\nb\"}",
    );

    var buffer: [4096]u8 = undefined;
    const wrote = try pair.harnessWrote(io, &buffer);
    // One line, so the newline inside the model's own text was escaped and did
    // not become a second message.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wrote, "\n"));
    try testing.expect(std.mem.indexOf(u8, wrote, "\"index\":3") != null);
    try testing.expect(std.mem.indexOf(u8, wrote, "path") != null);
}

test "a driver whose process never started answers gone, and says so once" {
    // A plugin whose host cannot start must answer and never wait, and it must
    // keep the first reason. `chock_core.helper.Helper` is not restarted, so
    // neither is this.
    //
    // **This test says nothing on the terminal, and that is not an accident.**
    // The root below is a path that is not there, so the sandbox child fails
    // while it builds the mount tree and writes the reason where
    // `Sandbox.Config.stderr_fd` says, which `helper.startWith` points at
    // `/dev/null`. `lib/chock-core/mcp_driver.zig` has the same case and says
    // in full why the child writes it the way it does.
    const gpa = testing.allocator;
    var process = helper.Helper.init(gpa);
    defer process.deinit(testing.io);

    var driver = Driver.init(gpa, &process, .{
        .config = .{ .root = "/nowhere", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} },
        .argv = &.{"/probe"},
    });
    defer driver.deinit();

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    const host = driver.host();
    try testing.expectError(error.Gone, host.call(
        arena_state.allocator(),
        testing.io,
        0,
        "hello",
        "{}",
        plugin.call_budget_ns,
    ));
    try testing.expect(driver.failure != null);
    try testing.expectEqualStrings(plugin.start_failed, driver.failure.?);

    // And it stays gone, without touching the process again.
    try testing.expectError(error.Gone, host.call(
        arena_state.allocator(),
        testing.io,
        0,
        "hello",
        "{}",
        plugin.call_budget_ns,
    ));
}

test "the lockdown takes the network and every rule the caller's config carried" {
    // A guest owns the address space of the process that runs it, so this
    // config is built by taking things away from a tool call's own and never
    // by adding to a blank one: a plugin must reach nothing a tool call
    // cannot, and then less.
    //
    // Mutation check: carry `config.rules` through and a plugin host reaches
    // every path a tool call reaches, the workspace included, with a hostile
    // guest holding the process.
    const permissive: sandbox.Config = .{
        .root = "/tmp/root",
        .mounts = &.{},
        .rules = &.{
            .{ .path = "/work", .access = sandbox.landlock.AccessFs.read_write },
        },
        .cwd = "/work",
        .env = &.{"PATH=/bin"},
        .network = .host,
    };
    const locked = try lockdown(testing.allocator, permissive, &.{});
    defer testing.allocator.free(locked.rules);

    try testing.expect(locked.network == .none);
    try testing.expectEqual(@as(usize, 0), locked.rules.len);
    // And what it must not change: the root, the working directory and the
    // environment are the caller's, so a plugin is inside the same world a
    // tool call is inside.
    try testing.expectEqualStrings("/tmp/root", locked.root);
    try testing.expectEqualStrings("/work", locked.cwd);
    try testing.expectEqual(@as(usize, 1), locked.env.len);
}

test "a writable path the caller states comes back read only" {
    // The caller states what the plugin host reaches, because a process with no
    // rule at all cannot even be executed. **The write rights are still not the
    // caller's to give**: a plugin's whole effect on the machine is the text of
    // its answer, and a guest owns this process.
    //
    // Mutation check: hand `reach` through unchanged and a plugin host can
    // write, delete and rename inside whatever path the caller named.
    const base: sandbox.Config = .{
        .root = "/tmp/root",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    };
    const locked = try lockdown(testing.allocator, base, &.{
        .{ .path = "/plugin.wasm", .access = sandbox.landlock.AccessFs.read_write },
        // `chock` itself, which is the program a plugin host process runs: see
        // `verb`. The name matters to nobody here, and it is the production
        // one so a reader of this test reads the production shape.
        .{ .path = "/chock", .access = .{ .execute = true, .read_file = true } },
    });
    defer testing.allocator.free(locked.rules);

    try testing.expectEqual(@as(usize, 2), locked.rules.len);
    try testing.expectEqualStrings("/plugin.wasm", locked.rules[0].path);
    try testing.expect(locked.rules[0].access.read_file);
    try testing.expect(!locked.rules[0].access.write_file);
    try testing.expect(!locked.rules[0].access.remove_file);
    try testing.expect(!locked.rules[0].access.truncate);
    try testing.expect(!locked.rules[0].access.refer);
    try testing.expect(!locked.rules[0].access.make_reg);
    // The execute right survives, and it has to: without it `execve` on the
    // host program itself is refused before anything runs.
    try testing.expect(locked.rules[1].access.execute);
    try testing.expect(locked.rules[1].access.read_file);
}

test "readOnly keeps only the three rights that read something" {
    // Written the safe way round on purpose: a right the kernel gains tomorrow
    // is refused here until somebody decides it belongs.
    const every = readOnly(sandbox.landlock.AccessFs.all);
    try testing.expect(every.execute);
    try testing.expect(every.read_file);
    try testing.expect(every.read_dir);

    var left = every;
    left.execute = false;
    left.read_file = false;
    left.read_dir = false;
    try testing.expectEqual(@as(u64, 0), left.bits());
}

test "a line that never ends is refused rather than grown until the machine complains" {
    // The host process is a program this project ships, so this is a bound
    // against a fault and not against malice. It still has to exist: a guest
    // that corrupted its host's own buffers could make it write forever.
    //
    // A thread writes, because more than a pipe's own buffer has to cross and
    // a pipe holds only about 64 KiB. Nothing here measures a duration.
    //
    // Mutation check: drop the `max_inbox_bytes` check in `receive` and this
    // test never finishes.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const Flood = struct {
        fn run(file: std.Io.File, driver: std.Io) void {
            var block: [64 << 10]u8 = @splat('x');
            var written: usize = 0;
            while (written < max_inbox_bytes + block.len) : (written += block.len) {
                std.Io.File.writeStreamingAll(file, driver, &block) catch return;
            }
        }
    };
    const thread = try std.Thread.spawn(.{}, Flood.run, .{ pair.host_writes, io });
    defer thread.join();

    try testing.expectError(error.Gone, protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        0,
        "{}",
    ));
    try testing.expect(pair.channel.poisoned);

    std.Io.File.close(pair.channel.from_helper, io);
    pair.channel.from_helper = .{ .handle = -1, .flags = .{ .nonblocking = false } };
}

test "the program that is running is the answer, and never whatever argv[0] named" {
    // **The fault this exists for.** `argv[0]` is `chock` for a person who ran
    // it off their `PATH`, and it is whatever a caller felt like putting there
    // for anybody else. A path a plugin host is started from that came out of
    // `argv[0]` would name a program this process did not run.
    //
    // `/proc/self/cmdline` is used as the wrong answer because it exists on
    // every Linux, resolves, and is certainly not the test binary.
    //
    // Mutation check: put `exe_path` first in the loop and the answer becomes
    // `/proc/<pid>/cmdline`.
    if (builtin.target.os.tag != .linux) {
        // There is no `/proc` here, and there is no plugin host process here
        // either: `Sandbox.spawn` refuses on Darwin. See `src/run.zig`'s own
        // `startPlugins`, which says so once at the start of a session.
        return error.SkipZigTest;
    }

    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const running = try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", arena);
    const answer = (try selfProgramPath(arena, io, "/proc/self/cmdline")).?;
    try testing.expectEqualStrings(running, answer);
}

test "a bare argv[0] still gives an absolute path, because a mount source has to be one" {
    // `chock_sandbox.namespace` asserts on a relative mount source, so a bare
    // `argv[0]` reaching that far is not one plugin that did not load: it is
    // the whole session ending on an assertion.
    //
    // Mutation check: answer `exe_path` unresolved and this reads `chock`.
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;

    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const answer = (try selfProgramPath(arena, io, "chock")).?;
    try testing.expect(std.fs.path.isAbsolute(answer));

    const running = try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", arena);
    try testing.expectEqualStrings(running, answer);
}

test "an empty argv[0] is not a candidate" {
    // A caller with nothing to offer offers nothing, rather than asking the
    // filesystem about the empty path and getting the working directory.
    //
    // Mutation check: drop the length check in the loop and the answer on a
    // platform with no `/proc` becomes whatever `realPathFileAlloc("")` gives.
    if (builtin.target.os.tag == .linux) {
        // `/proc/self/exe` answers first here, so the empty string is never
        // reached and this test would measure nothing.
        return error.SkipZigTest;
    }

    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();

    try testing.expectEqual(
        @as(?[]const u8, null),
        try selfProgramPath(arena_state.allocator(), io, ""),
    );
}

comptime {
    // Named here so a reader finds the other half of the boundary, and so the
    // two never drift into separate ideas of what a call is.
    _ = plugin_engine.max_imports;
}
