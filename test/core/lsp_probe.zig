//! A real language server in a real sandbox, and the harness half that drives
//! it. One program, two operations, so both ends of the pipe are the same binary
//! and the test needs nothing installed on the machine.
//!
//! The `serve` operation is not a real `zls`. It answers exactly what the driver
//! expects, because it was written to, so it cannot catch a real server that does
//! something reasonable the driver did not anticipate.
//! `test/core/lsp_zls_probe.zig` covers that class.
//!
//! Exit codes:
//!   0 - the operation did what the test expects.
//!   1 - it ran and the answer was wrong. The reason is on standard error.
//!   2 - the operation name on the command line is unknown.
//!   3 - the setup itself failed before anything was proven.
//!  63 - this machine would not give the sandbox its namespaces, so the caller
//!       skips. See `namespace.nothing_measured_exit_status`.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("chock-sandbox");
const chock_core = @import("chock-core");

/// No character in it needs JSON escaping, so `serve` needs no decoder.
const source_text = "const x = 1";

/// A real server resolves the path, so the driver builds its URI from the
/// sandbox side of the mount.
const sandbox_project = "/srv/project";

pub fn main(init: std.process.Init.Minimal) !u8 {
    return runOperation(init) catch |err| {
        // Nothing is printed here. `build.zig` fails the build on a byte a test
        // binary writes to standard error, and these descriptors are its own.
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

/// Raw reads and writes, no `std.Io` and no JSON parser. This runs inside the
/// sandbox, so a failure here has to be the sandbox or the pipe.
fn serve() u8 {
    var inbox: [64 * 1024]u8 = undefined;
    var filled: usize = 0;

    while (true) {
        if (takeMessage(inbox[0..filled])) |taken| {
            const body = inbox[taken.body_start..taken.end];

            if (std.mem.indexOf(u8, body, "\"method\":\"initialize\"") != null) {
                if (!replyToInitialize(body)) return 3;
            } else if (std.mem.indexOf(u8, body, "\"textDocument/didOpen\"") != null) {
                if (!publish(body)) return 3;
            } else if (std.mem.indexOf(u8, body, "\"textDocument/didClose\"") != null) {
                return 0;
            }

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
        if (count == 0) return 0;
        filled += count;
    }
}

const Taken = struct {
    body_start: usize,
    end: usize,
};

fn takeMessage(buffer: []const u8) ?Taken {
    const head_end = std.mem.indexOf(u8, buffer, "\r\n\r\n") orelse return null;
    const marker = "Content-Length:";
    const at = std.mem.indexOf(u8, buffer[0..head_end], marker) orelse return null;
    var digits = buffer[at + marker.len .. head_end];
    digits = std.mem.trim(u8, digits, " \t\r\n");
    var end_of_number: usize = 0;
    while (end_of_number < digits.len and std.ascii.isDigit(digits[end_of_number])) end_of_number += 1;
    const length = std.fmt.parseInt(usize, digits[0..end_of_number], 10) catch return null;

    const body_start = head_end + 4;
    if (buffer.len < body_start + length) return null;
    return .{ .body_start = body_start, .end = body_start + length };
}

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

fn fieldNumber(body: []const u8, name: []const u8) ?i64 {
    const at = std.mem.indexOf(u8, body, name) orelse return null;
    const rest = body[at + name.len ..];
    var end: usize = 0;
    while (end < rest.len and std.ascii.isDigit(rest[end])) end += 1;
    return std.fmt.parseInt(i64, rest[0..end], 10) catch null;
}

/// Still escaped, so it can go straight back out inside another JSON string.
fn fieldString(body: []const u8, name: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, body, name) orelse return null;
    const rest = body[at + name.len ..];
    const close = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    return rest[0..close];
}

/// One call, so a short write cannot leave a header on the wire with no body.
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

/// `work` is the host side of the workspace, which nothing inside ever sees.
fn drive(arena: std.mem.Allocator, root: []const u8, work: []const u8) !u8 {
    // The session carries on when a server does not start, so a machine with no
    // namespace would otherwise read as a server that said nothing. Asked in a
    // child, which is the only way to ask without spending this process's one
    // namespace.
    if (!sandbox.namespace.probeAvailability().available()) {
        return sandbox.namespace.nothing_measured_exit_status;
    }

    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var work_dir = try std.Io.Dir.cwd().openDir(io, work, .{});
    defer work_dir.close(io);
    try work_dir.createDirPath(io, "src");
    try work_dir.writeFile(io, .{ .sub_path = "src/main.zig", .data = source_text });

    const self_path = try selfExePath(arena);

    // The program this starts is a dynamically linked binary out of the store.
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

    // `/probe` holds a slash, so `prepare` reads it as a program already inside
    // the sandbox and binds nothing for it. The two extras below put it there.
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

    if (std.mem.indexOf(u8, block, "1 problem after this edit") == null) {
        std.debug.print("drive: no problem was reported: {s}\n", .{block});
        return 1;
    }
    if (std.mem.indexOf(u8, block, "src/main.zig:1:11: error: ") == null) {
        std.debug.print("drive: the diagnostic is in the wrong place: {s}\n", .{block});
        return 1;
    }
    if (std.mem.indexOf(u8, block, source_text) == null) {
        std.debug.print("drive: the file's text never reached the server: {s}\n", .{block});
        return 1;
    }

    return 0;
}

fn selfExePath(arena: std.mem.Allocator) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.readlink("/proc/self/exe", &buffer, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.SetupFailed;
    return arena.dupe(u8, buffer[0..rc]);
}
