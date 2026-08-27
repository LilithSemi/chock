//! A real language server in a real sandbox, and the harness half that drives
//! it. One program, two operations, so that both ends of the pipe are the same
//! binary and the test needs nothing installed on the machine.
//!
//! **This is the end to end proof that the LSP path works.**
//! Everything between the two operations is production code: `tools.prepare`
//! builds the sandbox, `helper.Helper` starts the process and holds the two
//! pipes, `lsp_driver.Driver` frames and parses the protocol, and
//! `lsp.Session` renders the block a model reads.
//!
//! **It is not a real `zls`.** The `serve` operation below speaks the smallest
//! part of the Language Server Protocol that a diagnostic needs: it answers
//! `initialize`, and it publishes one diagnostic when a document is opened.
//! **So it cannot catch the class of fault where a real server does something
//! reasonable the driver did not anticipate**: it answers exactly what the
//! driver expects, because it was written to. `test/core/lsp_zls_probe.zig` is
//! that class, with a real `zls` on the far side of the same pipe, and it
//! found three faults this file was passing over.
//!
//! Both are kept. This one needs nothing installed on the machine, so it runs
//! everywhere `Sandbox.spawn` does and proves the sandbox, the descriptor and
//! the framing on every machine.
//!
//! ## The one fact that only this test can prove
//!
//! The diagnostic `serve` publishes carries **the text of the file it was
//! given** as its message. So the block the harness reads back holds bytes
//! that went out of this process, through `sandbox.Config.stdin_fd`, into a
//! program inside a pivoted mount namespace under Landlock and seccomp, and
//! came back out again. A `stdin_fd` that arrived as `/dev/null` gives the
//! server nothing to read and this probe times out with no diagnostic at all.
//!
//! Exit codes:
//!   0 - the operation did what the test expects.
//!   1 - it ran and the answer was wrong. The reason is on standard error.
//!   2 - the operation name on the command line is unknown.
//!   3 - the setup itself failed before anything was proven.
//!  63 - this machine would not give the sandbox its namespaces, so nothing
//!       here was measured. **Not a pass and not a failure**: the caller
//!       skips. See `namespace.nothing_measured_exit_status`.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("chock-sandbox");
const chock_core = @import("chock-core");

/// The source file the driver asks about, and the text that has to survive the
/// round trip. **No character in it needs JSON escaping**, so `serve` can put
/// the escaped text it received straight back into the publication it builds
/// without decoding anything: see `serve`.
const source_text = "const x = 1";

/// Where the workspace appears inside the sandbox. Only the URIs on the wire
/// are built from it, because the server this probe runs reads no file: it is
/// handed the text. A real server resolves the path, which is why the driver
/// builds a URI from the sandbox side of the mount and never from the host
/// side.
const sandbox_project = "/srv/project";

pub fn main(init: std.process.Init.Minimal) !u8 {
    return runOperation(init) catch |err| {
        // **The machine, and not the feature.** A sandbox that cannot be
        // built at all means nothing this program is about ever ran. Its own
        // exit status, so the caller skips rather than read it as a wrong
        // answer. Nothing is printed: `build.zig`'s own `failOnTestStderr`
        // fails the build on a byte a test binary writes to standard error,
        // and this program's descriptors are that binary's own.
        if (err == error.NamespaceFailed) return sandbox.namespace.nothing_measured_exit_status;
        return err;
    };
}

fn runOperation(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("usage: lsp_probe <serve|drive> [root] [work]\n", .{});
        return 2;
    }

    if (std.mem.eql(u8, args[1], "serve")) return serve();
    if (std.mem.eql(u8, args[1], "drive")) {
        if (args.len != 4) {
            std.debug.print("usage: lsp_probe drive <root> <work>\n", .{});
            return 2;
        }
        return drive(arena, args[2], args[3]);
    }

    std.debug.print("unknown operation: {s}\n", .{args[1]});
    return 2;
}

/// Read framed messages from descriptor 0 and answer on descriptor 1, until
/// the document is closed or the pipe reaches end of file.
///
/// **Raw reads and writes, and no `std.Io`.** This runs inside the sandbox
/// with every layer applied, so the fewer mechanisms between it and the two
/// descriptors the better: a failure here has to be the sandbox or the pipe
/// and nothing else. No JSON parser either, for the same reason: the three
/// messages it answers are told apart by the method name in them, and the two
/// values it needs are read as substrings.
fn serve() u8 {
    var inbox: [64 * 1024]u8 = undefined;
    var filled: usize = 0;

    while (true) {
        // A whole message first, if one is already here.
        if (takeMessage(inbox[0..filled])) |taken| {
            const body = inbox[taken.body_start..taken.end];

            if (std.mem.indexOf(u8, body, "\"method\":\"initialize\"") != null) {
                if (!replyToInitialize(body)) return 3;
            } else if (std.mem.indexOf(u8, body, "\"textDocument/didOpen\"") != null) {
                if (!publish(body)) return 3;
            } else if (std.mem.indexOf(u8, body, "\"textDocument/didClose\"") != null) {
                return 0;
            }

            // Whatever follows the message just handled moves to the front.
            const rest = filled - taken.end;
            std.mem.copyForwards(u8, inbox[0..rest], inbox[taken.end..filled]);
            filled = rest;
            continue;
        }

        if (filled == inbox.len) return 3;
        const count = linux.read(std.posix.STDIN_FILENO, inbox[filled..].ptr, inbox.len - filled);
        const read_errno = linux.errno(count);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return 3;
        // End of file: the harness closed its end, which is how a helper is
        // told there is nothing more to answer.
        if (count == 0) return 0;
        filled += count;
    }
}

const Taken = struct {
    body_start: usize,
    end: usize,
};

/// Where the first whole message in `buffer` starts and ends, or null when a
/// whole one has not arrived. The same framing rule the driver keeps: the body
/// is only ever read once `Content-Length` bytes are really there.
fn takeMessage(buffer: []const u8) ?Taken {
    const head_end = std.mem.indexOf(u8, buffer, "\r\n\r\n") orelse return null;
    const marker = "Content-Length:";
    const at = std.mem.indexOf(u8, buffer[0..head_end], marker) orelse return null;
    var digits = buffer[at + marker.len .. head_end];
    digits = std.mem.trim(u8, digits, " \t\r\n");
    // Only the first line's worth of digits, in case another header follows.
    var end_of_number: usize = 0;
    while (end_of_number < digits.len and std.ascii.isDigit(digits[end_of_number])) end_of_number += 1;
    const length = std.fmt.parseInt(usize, digits[0..end_of_number], 10) catch return null;

    const body_start = head_end + 4;
    if (buffer.len < body_start + length) return null;
    return .{ .body_start = body_start, .end = body_start + length };
}

/// Answer `initialize` with the id it carried, so the driver's own wait for
/// that id ends. A reply with the wrong id, or none, leaves the driver waiting
/// out its whole budget, which is a real failure this probe would show.
fn replyToInitialize(body: []const u8) bool {
    const id = fieldNumber(body, "\"id\":") orelse return false;
    var out: [256]u8 = undefined;
    const text = std.fmt.bufPrint(
        &out,
        "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{{\"capabilities\":{{}}}}}}",
        .{id},
    ) catch return false;
    return writeFramed(text);
}

/// Publish one diagnostic for the document that was just opened, **carrying
/// the text that document was opened with**. See this file's own top comment:
/// that is what makes the round trip provable rather than assumed.
fn publish(body: []const u8) bool {
    const uri = fieldString(body, "\"uri\":\"") orelse return false;
    const text = fieldString(body, "\"text\":\"") orelse return false;

    var out: [8 * 1024]u8 = undefined;
    const message = std.fmt.bufPrint(
        &out,
        "{{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/publishDiagnostics\",\"params\":" ++
            "{{\"uri\":\"{s}\",\"diagnostics\":[{{\"range\":{{\"start\":{{\"line\":0,\"character\":10}}," ++
            "\"end\":{{\"line\":0,\"character\":11}}}},\"severity\":1,\"message\":\"{s}\"}}]}}}}",
        .{ uri, text },
    ) catch return false;
    return writeFramed(message);
}

/// The digits of a `"name":123` field, or null when it is not there.
fn fieldNumber(body: []const u8, name: []const u8) ?i64 {
    const at = std.mem.indexOf(u8, body, name) orelse return null;
    const rest = body[at + name.len ..];
    var end: usize = 0;
    while (end < rest.len and std.ascii.isDigit(rest[end])) end += 1;
    return std.fmt.parseInt(i64, rest[0..end], 10) catch null;
}

/// The content of a `"name":"value"` field, still escaped exactly as it
/// arrived, or null when it is not there.
///
/// **Still escaped is the point.** The value goes straight back out inside
/// another JSON string, so leaving it as it came keeps it valid without this
/// probe carrying a JSON encoder. A backslash before the closing quote would
/// break that, which is why `source_text` holds no character that needs one.
fn fieldString(body: []const u8, name: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, body, name) orelse return null;
    const rest = body[at + name.len ..];
    const close = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    return rest[0..close];
}

/// Write one message with its `Content-Length` header, in one call, so a short
/// write cannot leave a header on the wire with no body behind it.
fn writeFramed(body: []const u8) bool {
    var out: [16 * 1024]u8 = undefined;
    const framed = std.fmt.bufPrint(&out, "Content-Length: {d}\r\n\r\n{s}", .{ body.len, body }) catch return false;
    var written: usize = 0;
    while (written < framed.len) {
        const count = linux.write(std.posix.STDOUT_FILENO, framed[written..].ptr, framed.len - written);
        const write_errno = linux.errno(count);
        if (write_errno == .INTR) continue;
        if (write_errno != .SUCCESS) return false;
        if (count == 0) return false;
        written += count;
    }
    return true;
}

/// Start the server above as a real helper inside a real sandbox, ask it about
/// a real file, and check that the block a model would read holds what the
/// server said.
///
/// `root` is the sandbox root, which `Sandbox.spawn` builds a mount tree in.
/// `work` is the host side of the workspace, which the driver reads the file's
/// text from and which nothing inside the sandbox ever sees.
fn drive(arena: std.mem.Allocator, root: []const u8, work: []const u8) !u8 {
    // **A boundary that was never reached is not a boundary that held.** The
    // session above this program is built to carry on when a language server
    // does not start, on purpose, so a machine that will not give a sandbox
    // reads here as a server that said nothing rather than as a machine that
    // measured nothing. Asked first, and in a child, which is the only way to
    // ask without spending this process's own one namespace: see
    // `namespace.probeAvailability`.
    if (!sandbox.namespace.probeAvailability().available()) {
        return sandbox.namespace.nothing_measured_exit_status;
    }

    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The file a tool call would have just written. On the host, because that
    // is where the workspace's own work really is: see
    // `chock_workspace.Workspace.workPath`.
    var work_dir = try std.Io.Dir.cwd().openDir(io, work, .{});
    defer work_dir.close(io);
    try work_dir.createDirPath(io, "src");
    try work_dir.writeFile(io, .{ .sub_path = "src/main.zig", .data = source_text });

    const self_path = try selfExePath(arena);

    // The sandbox a tool call gets, built by the production function. The
    // store is here because the program this starts is a dynamically linked
    // binary out of it, exactly as a real language server is.
    const workspace_config = sandbox.Config{
        .root = root,
        .mounts = &.{
            .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
        },
        .rules = &.{
            .{ .path = "/nix/store", .access = sandbox.landlock.AccessFs.read_only },
        },
        .cwd = "/",
        .env = &.{},
    };

    var env = std.process.Environ.Map.init(arena);

    // `/probe` holds a slash, so `prepare` reads it as a program already
    // inside the sandbox and binds nothing for it. The bind and the rule that
    // really put it there are the two extras below, which is the same route
    // a write tool's own staged file takes.
    const prepared = try chock_core.tools.prepare(
        arena,
        io,
        &env,
        workspace_config,
        &.{ "/probe", "serve" },
        &.{.{ .bind = .{ .source = self_path, .target = "/probe", .read_only = true } }},
        &.{.{ .path = "/probe", .access = .{ .execute = true, .read_file = true } }},
    );

    var process = chock_core.helper.Helper.init(std.heap.page_allocator);
    defer process.deinit(io);

    var driver = chock_core.lsp_driver.Driver{
        .gpa = arena,
        .process = &process,
        .request = .{ .config = prepared.config, .argv = prepared.argv },
        .work_root = work,
        .sandbox_root = sandbox_project,
    };
    defer driver.deinit();

    var session = chock_core.lsp.Session{
        .program = "lsp-probe",
        .suffixes = &.{".zig"},
        .server = driver.server(),
    };

    const block = (try session.afterWrite(arena, io, "src/main.zig")) orelse {
        std.debug.print("drive: the session said nothing at all\n", .{});
        return 1;
    };

    // The block a model reads. Three separate facts, and each one is a
    // different part of the chain.
    //
    // 1. One problem was reported at all, so the whole round trip happened.
    if (std.mem.indexOf(u8, block, "1 problem after this edit") == null) {
        std.debug.print("drive: no problem was reported: {s}\n", .{block});
        return 1;
    }
    // 2. The path came back as the workspace relative one, out of a `file://`
    //    URI built from the sandbox side of the mount, and the line and the
    //    column are counted from one.
    if (std.mem.indexOf(u8, block, "src/main.zig:1:11: error: ") == null) {
        std.debug.print("drive: the diagnostic is in the wrong place: {s}\n", .{block});
        return 1;
    }
    // 3. **The file's own text came back**, which only happens if it really
    //    reached a program on the far side of `Config.stdin_fd`.
    if (std.mem.indexOf(u8, block, source_text) == null) {
        std.debug.print("drive: the file's text never reached the server: {s}\n", .{block});
        return 1;
    }

    return 0;
}

/// This binary's own path on the host, so it can be bound into the sandbox and
/// run again as the server. The same trick `test/sandbox/probe.zig` uses.
fn selfExePath(arena: std.mem.Allocator) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.readlink("/proc/self/exe", &buffer, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.SetupFailed;
    return arena.dupe(u8, buffer[0..rc]);
}
