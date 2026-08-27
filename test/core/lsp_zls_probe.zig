//! A **real `zls`**, in a real sandbox, driven by the production driver, over
//! the production seam, into the block a model reads.
//!
//! `test/core/lsp_probe.zig` is the same chain with a server written for the
//! test, and it says out loud what that leaves out: a probe answers exactly
//! what the driver expects, so it cannot catch the class of fault where a real
//! server does something reasonable the driver did not anticipate. This file
//! is that class, and it found one: see `Encoding` in
//! `lib/chock-core/lsp_driver.zig`.
//!
//! **Nothing here is provisioned and nothing here reaches the network.** The
//! `zls` this runs is one that is already on the machine, found on the dev
//! shell's own `PATH` when the project was built, and handed down as a path.
//! A test that fetched a language server would be a build and not a test, the
//! same rule `lib/chock-core/lsp.zig` states for its own seam.
//!
//! ## What a real server does that the written probe does not
//!
//! Every one of these was measured against `zls` 0.16 on 2026-08-22, and each
//! one is a message the driver has to walk past to reach its answer:
//!
//! * It writes `window/logMessage` and `window/showMessage` notifications
//!   **before** it answers `initialize`, so the reply is not the first message
//!   on the wire.
//! * It reports that it could not resolve a global cache directory, and that
//!   it could not find a `zig`, and then works anyway. Neither is fatal, and a
//!   driver that read a `showMessage` of type 1 as a failure would give up on
//!   a server that is about to answer correctly.
//! * It answers a full capability set, of which exactly one field matters:
//!   `positionEncoding`. See below.
//!
//! ## The fault this file exists to have caught
//!
//! **`zls` counts the `character` of a position in UTF-16 code units** unless
//! the client says it can read something else, because that is the protocol's
//! own default. A column in this project is a byte column. The two agree on
//! every ASCII line and disagree on every line that holds a character above
//! ASCII, which is why a suite written over ASCII never sees it.
//!
//! So `src/unicode.zig` below holds a four byte character before the mistake,
//! and the column it produces is checked against the byte. Measured: `zls`
//! reports character 26 when it counts UTF-16 and 28 when it counts bytes, and
//! the byte column of that `1` is 29 either way.
//!
//! Exit codes:
//!   0 - the operation did what the test expects.
//!   1 - it ran and the answer was wrong. The reason is on standard error.
//!   2 - the operation name on the command line is unknown.
//!   3 - the setup itself failed before anything was proven.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("chock-sandbox");
const chock_core = @import("chock-core");

/// Where the workspace appears inside the sandbox. A real server resolves the
/// paths in the URIs it is sent inside its own mount namespace, so this is the
/// path every URI is built from and never the host side of the mount.
const sandbox_project = "/srv/project";

/// A file with one real Zig mistake in it, all of it ASCII.
///
/// Measured: `zls` 0.16 answers `expected ';' after declaration` at line 0,
/// character 10, which is line 1 column 11 in the numbering a person reads.
const ascii_source = "const x = 1\n";

/// The same mistake with a four byte character in front of it, which is the
/// whole reason this file exists. The `1` is byte 28 of the line, counting
/// from zero, so its column is 29.
const unicode_source = "const a = \"\u{1F363}\"; const x = 1\n";

pub fn main(init: std.process.Init.Minimal) !u8 {
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

/// Start a real `zls` as a real helper inside a real sandbox, ask it about two
/// real files, and check the block a model would read for each.
///
/// `root` is the sandbox root, which `Sandbox.spawn` builds a mount tree in.
/// `work` is the host side of the workspace, which the driver reads a file's
/// text from and which the sandbox also carries, read only, at
/// `sandbox_project`.
fn drive(arena: std.mem.Allocator, root: []const u8, work: []const u8, zls: []const u8) !u8 {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The files a tool call would have just written, on the host, because that
    // is where the workspace's own work really is.
    var work_dir = try std.Io.Dir.cwd().openDir(io, work, .{});
    defer work_dir.close(io);
    try work_dir.createDirPath(io, "src");
    try work_dir.writeFile(io, .{ .sub_path = "src/main.zig", .data = ascii_source });
    try work_dir.writeFile(io, .{ .sub_path = "src/unicode.zig", .data = unicode_source });

    // The store, because a language server out of a Nix dev shell is a
    // dynamically linked binary in it, and the workspace, because a real
    // server reads the project. **An identity bind for the store**, so
    // `chock_core.tools.prepare` runs `zls` from its own store path with its
    // whole installation around it rather than from a copy: see that
    // function's own `alreadyMounted`.
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
        // **Empty, which is what a helper really gets today.** A helper is
        // built from the session's sandbox config the same way a tool call is,
        // and neither the cache directory nor the scratchpad reaches one: see
        // `chock_core.tools.Context.cache_dir`. Measured: `zls` says it could
        // not resolve a global cache directory and answers anyway.
        .env = &.{},
    };

    // The program name is resolved on this `PATH`, the same road
    // `src/run.zig` takes with the dev shell's own environment, so the argv
    // below is the bare name a `chock.zon` would hold and never a path.
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

    // The first ask carries the starting budget, and it is the one that pays
    // for the server starting up. The second carries the steady budget, so a
    // session that keeps working really is checked here and not only a session
    // that just began.
    if (!try check(arena, io, &session, "src/main.zig", "src/main.zig:1:11: error: expected ';'")) return 1;
    // **The same file a second time**, which is the ordinary case: an agent
    // edits one file several times in a session. A server that says something
    // about a document between two asks leaves it in the pipe, and a driver
    // that read it as this ask's answer would tell the model the file it just
    // broke is clean. Measured: `zls` publishes an empty list for a document
    // it is told to close.
    if (!try check(arena, io, &session, "src/main.zig", "src/main.zig:1:11: error: expected ';'")) return 1;
    if (!try check(arena, io, &session, "src/unicode.zig", "src/unicode.zig:1:29: error: expected ';'")) return 1;

    return 0;
}

/// Ask about one file and check the block a model would read. Answers false
/// once it has said what was wrong.
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

    // One problem, so the whole round trip happened and the count is the count
    // of what reached the model.
    if (std.mem.indexOf(u8, block, "1 problem after this edit") == null) {
        std.debug.print("drive: {s}: no problem was reported: {s}\n", .{ path, block });
        return false;
    }
    // The path, the line, the column and the severity, all from a real server.
    // **The column is the point for the unicode file**: see this file's own
    // top comment.
    if (std.mem.indexOf(u8, block, wanted) == null) {
        std.debug.print("drive: {s}: wanted {s}, got: {s}\n", .{ path, wanted, block });
        return false;
    }
    return true;
}
