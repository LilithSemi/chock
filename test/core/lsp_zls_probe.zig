//! A real `zls`, in a real sandbox, driven by the production driver, into the
//! block a model reads. `test/core/lsp_probe.zig` is the same chain with a
//! server written for the test, which cannot catch what a real server does.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("chock-sandbox");
const chock_core = @import("chock-core");

/// A real server resolves the URIs it is sent inside its own mount namespace,
/// so every URI is built from this path and never from the host side.
const sandbox_project = "/srv/project";

const ascii_source = "const x = 1\n";

/// `zls` counts `character` in UTF-16 code units unless the client asks for
/// something else, so it reports 26 for the `1` here and 28 when it counts
/// bytes. The byte column is 29. An all ASCII suite never sees the difference.
const unicode_source = "const a = \"\u{1F363}\"; const x = 1\n";

pub fn main(init: std.process.Init.Minimal) !u8 {
    return runOperation(init) catch |err| {
        // `build.zig` fails the build on any byte a test binary writes to
        // standard error, and these descriptors are that binary's own.
        if (err == error.NamespaceFailed) return sandbox.namespace.nothing_measured_exit_status;
        return err;
    };
}

fn runOperation(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.args.toSlice(arena);
    if (args.len != 5 or !std.mem.eql(u8, args[1], "drive")) {
        std.debug.print("usage: lsp_zls_probe drive <root> <work> <zls>\n", .{});
        return 2;
    }
    return drive(arena, args[2], args[3], args[4]);
}

/// `zls` is a path build.zig found on the dev shell's `PATH`. Nothing here
/// provisions a server or reaches a network.
fn drive(arena: std.mem.Allocator, root: []const u8, work: []const u8, zls: []const u8) !u8 {
    // Asked in a child, the only way to ask without spending this process's
    // one namespace. The session above cannot tell a silent server apart.
    if (!sandbox.namespace.probeAvailability().available()) {
        return sandbox.namespace.nothing_measured_exit_status;
    }

    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var work_dir = try std.Io.Dir.cwd().openDir(io, work, .{});
    defer work_dir.close(io);
    try work_dir.createDirPath(io, "src");
    try work_dir.writeFile(io, .{ .sub_path = "src/main.zig", .data = ascii_source });
    try work_dir.writeFile(io, .{ .sub_path = "src/unicode.zig", .data = unicode_source });

    // A dev shell server is a dynamically linked binary in the store, so the
    // store needs an identity bind and not a copy.
    const workspace_config = sandbox.Config{
        .root = root,
        .mounts = &.{
            .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
            .{ .bind = .{ .source = work, .target = sandbox_project, .read_only = true } },
        },
        .rules = &.{
            .{ .path = "/nix/store", .access = sandbox.landlock.AccessFs.read_only },
            .{ .path = sandbox_project, .access = sandbox.landlock.AccessFs.read_only },
        },
        .cwd = sandbox_project,
        // `zls` reports no global cache directory here and answers anyway.
        .env = &.{},
    };

    var env = std.process.Environ.Map.init(arena);
    const bin_dir = std.fs.path.dirname(zls) orelse {
        std.debug.print("drive: {s} names no directory\n", .{zls});
        return 3;
    };
    try env.put("PATH", bin_dir);
    const program = std.fs.path.basename(zls);

    const prepared = chock_core.tools.prepare(
        arena,
        io,
        &env,
        workspace_config,
        &.{program},
        &.{},
        &.{},
    ) catch |err| {
        std.debug.print("drive: the server could not be prepared: {t}\n", .{err});
        return 3;
    };

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
        .program = program,
        .suffixes = &.{".zig"},
        .server = driver.server(),
    };

    if (!try check(arena, io, &session, "src/main.zig", "src/main.zig:1:11: error: expected ';'")) return 1;
    // `zls` publishes an empty diagnostic list for a closed document, and that
    // message sits in the pipe before this second ask.
    if (!try check(arena, io, &session, "src/main.zig", "src/main.zig:1:11: error: expected ';'")) return 1;
    if (!try check(arena, io, &session, "src/unicode.zig", "src/unicode.zig:1:29: error: expected ';'")) return 1;

    return 0;
}

fn check(
    arena: std.mem.Allocator,
    io: std.Io,
    session: *chock_core.lsp.Session,
    path: []const u8,
    wanted: []const u8,
) !bool {
    const block = (try session.afterWrite(arena, io, path)) orelse {
        std.debug.print("drive: {s}: the session said nothing at all\n", .{path});
        return false;
    };

    if (std.mem.indexOf(u8, block, "1 problem after this edit") == null) {
        std.debug.print("drive: {s}: no problem was reported: {s}\n", .{ path, block });
        return false;
    }
    if (std.mem.indexOf(u8, block, wanted) == null) {
        std.debug.print("drive: {s}: wanted {s}, got: {s}\n", .{ path, wanted, block });
        return false;
    }
    return true;
}
