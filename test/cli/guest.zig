//! A real guest, booted through the real `chock daemon`, with one real tool call inside it.
//! It reads no credential and reaches none: the provider is a local fake, and `HOME`, `TMPDIR`
//! and every `XDG_*` directory point inside a temporary directory of their own.

const std = @import("std");
const builtin = @import("builtin");

const control = @import("chock-proto").control;

const gate = @import("guest_gate");
/// The binary that was just built, as a build time constant, since Zig 0.16's test runner takes no argument.
const chock_path = gate.chock_path;
/// Found by `build.zig`. An empty string means the machine has none, which is a reason to skip.
const git_path = gate.git_path;
const wc_path = gate.wc_path;
/// From `-Dguest-kernel=` and `-Dguest-initrd=`, empty when nobody passed them.
const kernel_path = gate.guest_kernel;
const initrd_path = gate.guest_initrd;

const testing = std.testing;

/// Long enough for a kernel to boot between the first provider request and the second.
const step_ms: i32 = 120 * 1000;

/// The most of a session log this reads, far past any one turn.
const max_events_bytes: usize = 64 * 1024 * 1024;

/// How long to wait for the daemon's socket to appear, in twenty millisecond steps.
const listen_steps: usize = 1500;

/// Every fact this gate needs, each named. Null when a guest can run here.
fn whyNoGuest(io: std.Io) ?[]const u8 {
    if (builtin.os.tag != .linux) return "a guest is Linux, and this host is not";
    if (chock_path.len == 0) return "no chock binary was named";
    if (git_path.len == 0) return "this machine has no git, so no workspace is built";
    if (wc_path.len == 0) return "this machine has no wc, so there is nothing to call";
    if (kernel_path.len == 0 or initrd_path.len == 0) {
        return "no guest images: pass -Dguest-kernel= and -Dguest-initrd=, " ++
            "built by nix build .#guest-kernel .#guest-initrd";
    }
    for ([_][]const u8{ kernel_path, initrd_path }) |path| {
        const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch
            return "a guest image was named that this machine cannot read";
        if (stat.size == 0) return "a guest image was named that holds nothing";
    }
    // This is why the gate skips rather than fails inside a Nix builder, whose sandbox has no /dev/kvm.
    const kvm = std.Io.Dir.openFileAbsolute(io, "/dev/kvm", .{}) catch
        return "this machine has no /dev/kvm this user may open";
    kvm.close(io);
    return null;
}

/// An isolated home, state and configuration tree, built from nothing rather than copied.
const Home = struct {
    tmp: testing.TmpDir,
    root: []u8,
    env: std.process.Environ.Map,

    fn init(gpa: std.mem.Allocator, io: std.Io) !Home {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try tmp.dir.realPath(io, &buffer);
        const root = try gpa.dupe(u8, buffer[0..length]);
        errdefer gpa.free(root);

        var env = std.process.Environ.Map.init(gpa);
        errdefer env.deinit();
        try env.put("HOME", root);
        try env.put("XDG_CONFIG_HOME", root);
        try env.put("XDG_DATA_HOME", root);
        try env.put("XDG_STATE_HOME", root);
        try env.put("XDG_CACHE_HOME", root);
        // `TMPDIR` inside the tree, so a staged file lands nowhere near the user's own.
        const tmpdir = try std.fmt.allocPrint(gpa, "{s}/tmp", .{root});
        defer gpa.free(tmpdir);
        try std.Io.Dir.cwd().createDirPath(io, tmpdir);
        try env.put("TMPDIR", tmpdir);
        // A test binary has no environment to search, so the spawned programs are named by their own directories.
        const path = try std.fmt.allocPrint(gpa, "{s}:{s}", .{
            std.fs.path.dirname(wc_path) orelse "/usr/bin",
            std.fs.path.dirname(git_path) orelse "/usr/bin",
        });
        defer gpa.free(path);
        try env.put("PATH", path);

        return .{ .tmp = tmp, .root = root, .env = env };
    }

    fn deinit(self: *Home, gpa: std.mem.Allocator) void {
        gpa.free(self.root);
        self.env.deinit();
        self.tmp.cleanup();
    }

    /// The provider, the model and the guest images. Nothing else, and no token.
    fn writeConfig(self: *Home, gpa: std.mem.Allocator, io: std.Io, port: u16) !void {
        const dir = try std.fmt.allocPrint(gpa, "{s}/chock", .{self.root});
        defer gpa.free(dir);
        try std.Io.Dir.cwd().createDirPath(io, dir);

        const path = try std.fmt.allocPrint(gpa, "{s}/config.zon", .{dir});
        defer gpa.free(path);

        var file = try std.Io.Dir.createFileAbsolute(io, path, .{
            .permissions = @enumFromInt(0o600),
        });
        defer file.close(io);
        var buffer: [1024]u8 = undefined;
        var writing = file.writerStreaming(io, &buffer);
        try writing.interface.print(
            \\.{{
            \\    .providers = .{{
            \\        .{{ .name = "gate", .kind = "openai-compat",
            \\           .base_url = "http://127.0.0.1:{d}/v1", .context_tokens = 65536 }},
            \\    }},
            \\    .defaults = .{{ .provider = "gate", .model = "gate-model" }},
            \\    .sandbox = .{{ .driver = "microvm", .kernel = "{s}", .initrd = "{s}" }},
            \\}}
            \\
        , .{ port, kernel_path, initrd_path });
        try writing.interface.flush();
    }
};

/// A git repository with one commit, a `chock.zon` that allows the call, and a `flake.nix` if asked for.
fn makeProject(
    gpa: std.mem.Allocator,
    io: std.Io,
    home: *Home,
    name: []const u8,
    with_flake: bool,
) ![]u8 {
    const path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ home.root, name });
    errdefer gpa.free(path);
    try std.Io.Dir.cwd().createDirPath(io, path);

    var dir = try std.Io.Dir.cwd().openDir(io, path, .{});
    defer dir.close(io);

    try dir.writeFile(io, .{ .sub_path = "README.md", .data = "a project with one commit\n" });
    // A filtered router is stated rather than inferred from a rule, since the staged trust store is what this call reads.
    try dir.writeFile(io, .{
        .sub_path = "chock.zon",
        .data =
        \\.{
        \\    .policy = .{
        \\        .net = .{ .router = .filtered },
        \\        .rules = .{
        \\            .{ .action = "exec.*", .decision = .allow },
        \\        },
        \\    },
        \\}
        \\
        ,
    });
    if (with_flake) {
        // A flake with no dev shell, covering the other half of the fork `DevShell.hasFlake` forks on.
        try dir.writeFile(io, .{ .sub_path = "flake.nix", .data = "{ outputs = { self }: { }; }\n" });
    }

    // The commit identity is on the command line, so no git configuration of anybody's is read.
    try git(gpa, io, &home.env, path, &.{ "init", "--quiet", "." });
    try git(gpa, io, &home.env, path, &.{ "add", "-A" });
    try git(gpa, io, &home.env, path, &.{
        "-c",     "user.email=gate@example.invalid",
        "-c",     "user.name=gate",
        "commit", "--quiet",
        "-m",     "one",
    });
    return path;
}

fn git(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    args: []const []const u8,
) !void {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.append(gpa, git_path);
    try argv.appendSlice(gpa, args);

    const result = try std.process.run(gpa, io, .{
        .argv = argv.items,
        .environ_map = env,
        .cwd = .{ .path = cwd },
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
}

fn httpChunk(comptime bytes: []const u8) []const u8 {
    return std.fmt.comptimePrint("{x}\r\n{s}\r\n", .{ bytes.len, bytes });
}

const response_head =
    "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: text/event-stream\r\n" ++
    "Cache-Control: no-cache\r\n" ++
    "Transfer-Encoding: chunked\r\n\r\n";

/// A multiline literal, which has no escape processing, so `arguments` carries the JSON a provider really sends.
const tool_call_line =
    \\data: {"choices":[{"index":0,"finish_reason":null,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"run_command","arguments":"{\"argv\":[\"wc\",\"-c\",\"/run/chock/ca-bundle.crt\"]}"}}]}}]}
;

const tool_call_turn = httpChunk(tool_call_line ++ "\n\n") ++
    httpChunk(
        \\data: {"choices":[{"index":0,"finish_reason":"tool_calls","delta":{}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}
    ++ "\n\n") ++
    httpChunk("data: [DONE]\n\n") ++ "0\r\n\r\n";

const closing_turn = httpChunk(
    \\data: {"choices":[{"index":0,"finish_reason":null,"delta":{"content":"the gate is through"}}]}
++ "\n\n") ++
    httpChunk(
        \\data: {"choices":[{"index":0,"finish_reason":"stop","delta":{}}],"usage":{"prompt_tokens":20,"completion_tokens":3,"total_tokens":23}}
    ++ "\n\n") ++
    httpChunk("data: [DONE]\n\n") ++ "0\r\n\r\n";

/// Wait for one descriptor to become readable. False when the time ran out.
fn readableWithin(handle: std.posix.fd_t, milliseconds: i32) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = std.posix.poll(&fds, milliseconds) catch return false;
    return ready != 0;
}

/// Answer one chat completion request with `turn`. The request body is read and dropped.
fn answerOneRequest(io: std.Io, server: *std.Io.net.Server, turn: []const u8) !void {
    if (!readableWithin(server.socket.handle, step_ms)) return error.ProviderNeverAsked;
    var stream = try server.accept(io);
    defer stream.close(io);

    var read_buffer: [16 * 1024]u8 = undefined;
    var reading = stream.reader(io, &read_buffer);
    const reader = &reading.interface;

    var content_length: usize = 0;
    while (true) {
        const line = std.mem.trimEnd(u8, try reader.takeDelimiterInclusive('\n'), "\r\n");
        if (line.len == 0) break;
        const prefix = "content-length:";
        if (std.ascii.startsWithIgnoreCase(line, prefix)) {
            content_length = std.fmt.parseInt(u64, std.mem.trim(u8, line[prefix.len..], " "), 10) catch 0;
        }
    }
    try reader.discardAll(content_length);

    var write_buffer: [8 * 1024]u8 = undefined;
    var writing = stream.writer(io, &write_buffer);
    try writing.interface.writeAll(response_head);
    try writing.interface.writeAll(turn);
    try writing.interface.flush();
}

/// Greet the daemon and send one request, over a connection of its own. The bytes are composed by `chock_proto.control`.
fn ask(gpa: std.mem.Allocator, io: std.Io, socket: []const u8, request: control.Request) !struct {
    stream: std.Io.net.Stream,
    reply: []u8,
} {
    var stream = try (control.Address{ .unix = socket }).connect(io);
    errdefer stream.close(io);

    var out: [4096]u8 = undefined;
    var sending = stream.writer(io, &out);
    try (control.Greeting{}).write(.ask, &sending.interface);
    try request.write(&sending.interface);
    try sending.interface.flush();

    // The greeting answer and the request's first line, in that order.
    var seen: std.ArrayList(u8) = .empty;
    errdefer seen.deinit(gpa);
    var newlines: usize = 0;
    while (newlines < 2) {
        if (!readableWithin(stream.socket.handle, step_ms)) return error.DaemonSaidNothing;
        var buffer: [4096]u8 = undefined;
        const got = std.posix.read(stream.socket.handle, &buffer) catch return error.DaemonSaidNothing;
        if (got == 0) break;
        try seen.appendSlice(gpa, buffer[0..got]);
        newlines = std.mem.count(u8, seen.items, "\n");
    }
    return .{ .stream = stream, .reply = try seen.toOwnedSlice(gpa) };
}

/// The second line of what `ask` read: `ok <session id>\t<log path>`, or an `error <sentence>`.
fn replyLine(reply: []const u8) []const u8 {
    var lines = std.mem.splitScalar(u8, reply, '\n');
    _ = lines.next();
    return std.mem.trimEnd(u8, lines.next() orelse "", "\r");
}

/// Read a watch connection to the end. The daemon closes it when the session ends.
fn drain(gpa: std.mem.Allocator, handle: std.posix.fd_t, already: []const u8) ![]u8 {
    var seen: std.ArrayList(u8) = .empty;
    errdefer seen.deinit(gpa);
    try seen.appendSlice(gpa, already);

    while (seen.items.len < max_events_bytes) {
        if (!readableWithin(handle, step_ms)) return error.WatchWentQuiet;
        var buffer: [16 * 1024]u8 = undefined;
        const got = std.posix.read(handle, &buffer) catch break;
        if (got == 0) break;
        try seen.appendSlice(gpa, buffer[0..got]);
    }
    return seen.toOwnedSlice(gpa);
}

/// One whole session: start the daemon, let it fork a guest, and hand back the session log and what it printed.
const Run = struct {
    events: []u8,
    said: []u8,

    fn deinit(self: *Run, gpa: std.mem.Allocator) void {
        gpa.free(self.events);
        gpa.free(self.said);
    }
};

fn runOneSession(gpa: std.mem.Allocator, io: std.Io, home: *Home, project: []const u8) !Run {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var provider = try address.listen(io, .{ .reuse_address = true });
    defer provider.deinit(io);
    try home.writeConfig(gpa, io, provider.socket.address.getPort());

    const socket = try std.fmt.allocPrint(gpa, "{s}/daemon.sock", .{home.root});
    defer gpa.free(socket);

    // Both streams into one file, so a kernel's boot log cannot fill a pipe and stop it.
    var said_file = try home.tmp.dir.createFile(io, "daemon.log", .{ .read = true });
    defer said_file.close(io);

    var daemon = try std.process.spawn(io, .{
        .argv = &.{ chock_path, "daemon", "--socket", socket, "--verbose", "--color=never" },
        .environ_map = &home.env,
        .stdin = .ignore,
        .stdout = .{ .file = said_file },
        .stderr = .{ .file = said_file },
    });
    // `kill` reaps, so there is never a `wait` beside it.
    var reaped = false;
    defer if (!reaped) daemon.kill(io);

    // The socket appearing is the daemon being ready to answer.
    var step: usize = 0;
    while (true) {
        if (std.Io.Dir.cwd().statFile(io, socket, .{})) |_| break else |_| {}
        step += 1;
        if (step > listen_steps) return error.DaemonNeverListened;
        std.Io.sleep(io, .fromMilliseconds(20), .real) catch {};
    }

    var started = try ask(gpa, io, socket, .{
        .start = .{ .project = project, .message = "boot a guest and count the bundle" },
    });
    defer gpa.free(started.reply);
    started.stream.close(io);

    const line = replyLine(started.reply);
    if (!std.mem.startsWith(u8, line, "ok ")) return error.SessionRefused;
    const rest = line["ok ".len..];
    const session = rest[0 .. std.mem.indexOfScalar(u8, rest, '\t') orelse rest.len];

    // The two provider turns the loop makes: the tool call, then the reply that ends it.
    try answerOneRequest(io, &provider, tool_call_turn);
    try answerOneRequest(io, &provider, closing_turn);

    var watching = try ask(gpa, io, socket, .{
        .watch = .{ .project = project, .session = session, .after = 0 },
    });
    defer watching.stream.close(io);
    defer gpa.free(watching.reply);

    const events = try drain(gpa, watching.stream.socket.handle, watching.reply);
    errdefer gpa.free(events);

    daemon.kill(io);
    reaped = true;

    const said = try home.tmp.dir.readFileAlloc(io, "daemon.log", gpa, .limited(8 * 1024 * 1024));
    return .{ .events = events, .said = said };
}

/// What `run_command` writes in front of a program's output, in the session log, with the newline escaped.
const result_prefix = "exit status: 0\\n";

/// The most of a run that is quoted when something is wrong, since the end of each log is where the fault is.
const quoted_bytes: usize = 4096;

fn tail(text: []const u8) []const u8 {
    return text[text.len -| quoted_bytes..];
}

/// Every claim this gate makes, checked against one run.
fn expectAGuestRanTheCall(gpa: std.mem.Allocator, run: *const Run) !void {
    var wrong: std.ArrayList(u8) = .empty;
    defer wrong.deinit(gpa);

    // A native tool call would also exit 0, so the guest is proven first.
    if (std.mem.indexOf(u8, run.said, "tool calls run in a microVM guest") == null) {
        try wrong.print(gpa, "the session never attached a guest:\n{s}\n", .{tail(run.said)});
    }
    if (std.mem.indexOf(u8, run.said, "Linux version ") == null) {
        try wrong.print(gpa, "no kernel printed a banner:\n{s}\n", .{tail(run.said)});
    }

    // Read after the exit status, so a check for the path alone cannot pass on a call that failed.
    if (std.mem.indexOf(u8, run.events, result_prefix)) |result| {
        const counted = run.events[result + result_prefix.len ..];
        var digits: usize = 0;
        while (digits < counted.len and std.ascii.isDigit(counted[digits])) digits += 1;
        const bytes = std.fmt.parseInt(u64, counted[0..digits], 10) catch 0;
        if (bytes == 0) try wrong.appendSlice(gpa, "wc counted no bytes in the staged bundle\n");
        if (!std.mem.startsWith(u8, counted[digits..], " /run/chock/ca-bundle.crt")) {
            try wrong.print(gpa, "the call counted something else: {s}\n", .{
                counted[0..@min(counted.len, 120)],
            });
        }
    } else {
        try wrong.print(gpa, "no tool call succeeded:\n{s}\n", .{tail(run.events)});
    }

    if (std.mem.indexOf(u8, run.events, "\"session.end\"") == null) {
        try wrong.appendSlice(gpa, "the session never ended\n");
    }

    try testing.expectEqualStrings("", wrong.items);
}

test "a project with no flake.nix boots a guest through the daemon and runs a routed call in it" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    if (whyNoGuest(io) != null) return error.SkipZigTest;

    var home = try Home.init(gpa, io);
    defer home.deinit(gpa);

    const project = try makeProject(gpa, io, &home, "plain", false);
    defer gpa.free(project);

    var run = try runOneSession(gpa, io, &home, project);
    defer run.deinit(gpa);
    try expectAGuestRanTheCall(gpa, &run);
}

test "a project with a flake.nix boots a guest through the daemon and runs a routed call in it" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    if (whyNoGuest(io) != null) return error.SkipZigTest;

    var home = try Home.init(gpa, io);
    defer home.deinit(gpa);

    const project = try makeProject(gpa, io, &home, "flaked", true);
    defer gpa.free(project);

    var run = try runOneSession(gpa, io, &home, project);
    defer run.deinit(gpa);
    try expectAGuestRanTheCall(gpa, &run);
}
