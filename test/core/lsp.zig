//! The language server, end to end, through a real sandbox.
//!
//! Linux only, because `Sandbox.spawn` is. Everything this suite drives lives
//! in `test/core/lsp_probe.zig`, in a process of its own: `Sandbox.spawn`
//! calls `fork`, and `fork` carries only the calling thread, so a lock another
//! thread of the test binary held at that moment would be copied into the
//! child as held forever. The same rule `test/core/tools.zig` already follows,
//! and the same reason.
//!
//! Two tests, and every other part is proven where it can be proven without a
//! sandbox: the protocol and the seam in `lib/chock-core/lsp_driver.zig`, the
//! lifecycle in `lib/chock-core/helper.zig`, the descriptor itself in
//! `test/sandbox/escape.zig`. What is left is the claim none of those can make
//! on its own, which is that all of it works together on a running system.
//!
//! The two differ in what is on the far side of the pipe:
//!
//! * `test/core/lsp_probe.zig` is a server written for the test. It answers
//!   exactly what the driver expects, which makes it a proof of the sandbox,
//!   the descriptor and the framing, and **not** a proof that the driver can
//!   talk to a server somebody else wrote.
//! * `test/core/lsp_zls_probe.zig` is a real `zls`. That is the whole class
//!   the written probe cannot reach, and it found a real fault: see that
//!   file's own top comment. It is **skipped** on a machine whose dev shell
//!   has no `zls`, because a test that provisions one is a build.

const std = @import("std");

// Zig 0.16 removed std.process.argsWithAllocator and the default test runner
// panics on any argv it does not recognize, so the probe's path is embedded at
// build time through an options module. See build.zig.
const probe_path = @import("lsp_probe_path").lsp_probe_path;

// The real `zls` half. Two build time constants, and the second one is null on
// a machine whose dev shell has no `zls` on its `PATH`: see build.zig, and see
// the test at the bottom of this file for why that is a skip and not a
// failure.
const zls_probe_path = @import("lsp_probe_path").lsp_zls_probe_path;
const zls_path: ?[]const u8 = @import("lsp_probe_path").zls_path;

// `chock-sandbox` for one question only: the exit status a probe answers with
// when this machine will not give it a sandbox at all.
const sandbox = @import("chock-sandbox");

/// Skip when a probe answered "this machine would not give me a sandbox".
///
/// **A boundary that was never reached is not a boundary that held.** The
/// tests here need a real sandbox to run a real server inside, so a machine
/// that refuses one measures nothing and must not report a pass. See
/// `namespace.nothing_measured_exit_status`, and the CI job named "Sandbox",
/// which runs this suite on a machine that can host one and fails rather than
/// skips.
fn skipIfNothingMeasured(term: std.process.Child.Term) !void {
    const code = switch (term) {
        .exited => |c| c,
        else => return,
    };
    if (code == sandbox.namespace.nothing_measured_exit_status) return error.SkipZigTest;
}

/// The absolute path of an already open directory. `std.testing.tmpDir` hands
/// back a directory only a relative path reaches, and both paths this test
/// passes down have to resolve the same way whatever the test binary's own
/// working directory is.
fn absoluteDirPath(buffer: []u8, dir: std.Io.Dir) ![]u8 {
    const len = dir.realPath(std.testing.io, buffer) catch return error.RealPathFailed;
    return buffer[0..len];
}

test "a real language server in a real sandbox puts a real diagnostic in a tool result" {
    // **The end to end proof, and the only test in this project that has one
    // for this feature.** The chain it exercises, in order:
    //
    // 1. `chock_core.tools.prepare` builds the same sandbox a tool call gets.
    // 2. `chock_core.helper.Helper` starts a program inside it that outlives
    //    one call, with a pipe on descriptor 0 and one on descriptor 1.
    // 3. `chock_core.lsp_driver.Driver` speaks the handshake, opens the
    //    document, and reads what the server publishes.
    // 4. `chock_core.lsp.Session` ranks it, bounds it, and renders the block a
    //    model reads.
    //
    // The probe checks three separate facts about that block and reports which
    // one failed on its own standard error. The strongest of them is that the
    // file's own text comes back inside the diagnostic: those bytes went
    // through `sandbox.Config.stdin_fd` into a pivoted mount namespace under
    // Landlock and seccomp, and came back out. A `stdin_fd` that arrived as
    // `/dev/null` leaves the server with nothing to read and no diagnostic to
    // publish.
    //
    // Mutation check: give `Config.stdin_fd` no effect in the Linux driver and
    // the probe reports that the session said nothing at all. Drop the
    // `didOpen` from the driver and the same. Report the wrong path or the
    // wrong line and the second check names it.
    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absoluteDirPath(&root_buffer, root_tmp.dir);
    const work = try absoluteDirPath(&work_buffer, work_tmp.dir);

    // Two directories and not one. `Sandbox.spawn` builds a mount tree under
    // the root it is given and removes what it built there when setup fails,
    // and the workspace on the host is not its to touch.
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ probe_path, "drive", root, work },
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(term);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a real zls in a real sandbox reports a real Zig error, in the right place" {
    // **The proof the test above cannot make.** The server here is one nobody
    // in this project wrote, so every message it sends is a message the driver
    // has to cope with rather than one it was built against, and the column it
    // reports is counted in units the driver has to ask about. See
    // `test/core/lsp_zls_probe.zig` for what was measured and for the fault
    // this found.
    //
    // **Skipped, never failed, on a machine with no `zls`.** The program comes
    // from the dev shell, which `pkgs/chock/default.nix` names it in, and a
    // test that provisioned one on every run would be a build. A skip is the
    // same answer the Darwin suites give for a thing that machine cannot do.
    //
    // Mutation check: the probe checks each fact on its own and says which one
    // failed on its own standard error. Put `.{}` back where `empty_object` is
    // in the driver's handshake and this reports that the server stopped
    // answering, which is what it did before that was found. Give
    // `Config.stdin_fd` no effect and it reports that the session said
    // nothing.
    //
    // **The column has two halves and either one alone gets it right**, so a
    // mutation of one is not visible here: offer no `positionEncodings` and
    // `byteColumn` converts the UTF-16 number, and skip the conversion and the
    // server was already asked for bytes. Remove both and the unicode file
    // reads 1:27 rather than 1:29, which was run. The half that the units
    // conversion carries on its own is pinned in
    // `lib/chock-core/lsp_driver.zig`, where a server states each encoding in
    // turn.
    const zls = zls_path orelse return error.SkipZigTest;

    var root_tmp = std.testing.tmpDir(.{});
    defer root_tmp.cleanup();
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absoluteDirPath(&root_buffer, root_tmp.dir);
    const work = try absoluteDirPath(&work_buffer, work_tmp.dir);

    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ zls_probe_path, "drive", root, work, zls },
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(term);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}
