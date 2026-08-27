//! The honest half of the git shim, on a running system.
//!
//! **The shim prevents a mistake. It does not prevent an attack.**
//! `lib/chock-broker/git_shim.zig` says so in its own top comment and names
//! the ways around itself one by one. This file takes the easiest of them,
//! naming the real git binary by its absolute path so the `PATH` is never
//! consulted, and shows that the push still does not happen.
//!
//! That is the whole point. If this test failed, the shim would be the only
//! thing standing between an agent and a push, and it is not a thing that can
//! stand there. The capability layers are the boundary.
//!
//! A real `Sandbox.spawn` call needs a single threaded caller, because `fork`
//! carries only the calling thread into the child, and the zig test runner is
//! not that caller. So the sandbox work goes through `escape_probe`, the same
//! program `test/workspace/escape.zig` and `test/broker/actions.zig` drive.
//! One probe, so no two suites can disagree about what a sandboxed process is
//! actually allowed to do.
//!
//! Every test here builds its own project inside a fresh
//! `std.testing.tmpDir` and sets its own `GIT_CEILING_DIRECTORIES`: Chock's
//! own checkout is a git repository, and `tmpDir` makes every scratch
//! directory somewhere underneath it, so git's upward search would otherwise
//! walk past a fresh scratch repository and find this project's real one.

const std = @import("std");
const chock_workspace = @import("chock-workspace");

const Workspace = chock_workspace.Workspace;
const testing = std.testing;

const support = @import("support.zig");

/// A listener on `127.0.0.1` that answers every connection with one short
/// reply and keeps the first bytes anybody sent it.
///
/// This exists so the test can say the strong thing rather than the weak
/// one. "The push failed" is weak: a push fails for many reasons. "The
/// remote was never contacted" is the fact this file needs, and only
/// something listening at the far end can report it.
///
/// It answers rather than only listening, because a mutation of this test
/// has to end. A sandbox that did have a route would otherwise leave git
/// waiting for a reply that never came, and a hanging test reports nothing.
const Recorder = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    server: std.Io.net.Server,
    port: u16,
    thread: std.Thread,
    stop: std.atomic.Value(bool),
    /// The first bytes any connection sent. Read only after `finish`.
    seen: std.ArrayList(u8),

    /// Enough of an HTTP reply that git gives up at once instead of waiting.
    const reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    fn start(gpa: std.mem.Allocator, io: std.Io) !*Recorder {
        const self = try gpa.create(Recorder);
        errdefer gpa.destroy(self);

        const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        const server = try address.listen(io, .{ .reuse_address = true });
        self.* = .{
            .io = io,
            .gpa = gpa,
            .server = server,
            .port = server.socket.address.getPort(),
            .thread = undefined,
            .stop = .init(false),
            .seen = .empty,
        };
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
        return self;
    }

    fn serve(self: *Recorder) void {
        while (!self.stop.load(.acquire)) {
            var stream = self.server.accept(self.io) catch return;
            defer stream.close(self.io);

            var read_buffer: [4096]u8 = undefined;
            var stream_reader = stream.reader(self.io, &read_buffer);
            // A connection that sends nothing and closes ends this at once,
            // which is exactly what the wake up connection in `finish` does,
            // so this never waits for a sender that will not send.
            const first = stream_reader.interface.takeDelimiterExclusive('\n') catch "";
            if (first.len > 0 and self.seen.items.len == 0) {
                self.seen.appendSlice(self.gpa, first) catch {};
            }

            var write_buffer: [256]u8 = undefined;
            var stream_writer = stream.writer(self.io, &write_buffer);
            stream_writer.interface.writeAll(reply) catch {};
            stream_writer.interface.flush() catch {};
        }
    }

    /// Prove the address was still live, then stop the thread. The one
    /// connection this makes is both: `accept` is waiting for it, and a
    /// connection that succeeds is what "live" means.
    fn finish(self: *Recorder) !void {
        self.stop.store(true, .release);
        const address = try std.Io.net.IpAddress.parse("127.0.0.1", self.port);
        var stream = try address.connect(self.io, .{ .mode = .stream });
        stream.close(self.io);
        self.thread.join();
    }

    fn deinit(self: *Recorder) void {
        self.seen.deinit(self.gpa);
        self.server.deinit(self.io);
        self.gpa.destroy(self);
    }
};

test "the real git run by its absolute path skips the shim, and the push still fails because there is no network" {
    // Three facts, and the test is worth nothing without all three.
    //
    // 1. The address is live on this machine, so a refusal below is a
    //    refusal and not a port that was never there.
    // 2. The sandbox has no route to it. The probe's `connect` op gets
    //    ENETUNREACH, the errno a network namespace with no route gives.
    // 3. The real git, named by its absolute path with no shim anywhere near
    //    it, runs fine inside that sandbox and still cannot push to the same
    //    address.
    //
    // Together those say: the way around the shim is easy and it leads
    // nowhere. Drop the network namespace and fact 2 and fact 3 both change.
    const gpa = testing.allocator;
    const io = testing.io;

    const git_path = (try support.findGitOnPath(gpa, io)) orelse {
        // A skip needs no message: a test that writes to standard error and
        // passes still puts a `failed command:` line in the build log.
        return error.SkipZigTest;
    };
    defer gpa.free(git_path);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try support.TestProject.init(gpa, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(
        gpa,
        io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        null,
    );
    defer workspace.close(gpa, io, &project.env, null) catch unreachable;

    var recorder = try Recorder.start(gpa, io);
    defer recorder.deinit();
    const port = recorder.port;

    var probe_root_tmp = testing.tmpDir(.{});
    defer probe_root_tmp.cleanup();

    var address_buffer: [32]u8 = undefined;
    const address_text = try std.fmt.bufPrint(&address_buffer, "127.0.0.1:{d}", .{port});
    const connect_term = try support.runProbe(gpa, &workspace, probe_root_tmp, "connect", address_text);
    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, connect_term);

    const url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/repo.git", .{port});
    defer gpa.free(url);
    const target = try std.fmt.allocPrint(gpa, "{s}\x01{s}", .{ git_path, url });
    defer gpa.free(target);

    const push_term = try support.runProbe(gpa, &workspace, probe_root_tmp, "git-push", target);
    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, push_term);

    try recorder.finish();
    try testing.expectEqualStrings("", recorder.seen.items);

    // The sandbox is not a deny all. A write inside the worktree still works,
    // so the two refusals above are the network layer refusing and not a
    // sandbox that had simply stopped working.
    const wt = workspace.kind.worktree;
    const inside_worktree = try std.fs.path.join(gpa, &.{ wt.project_root, "chock-shim-test.txt" });
    defer gpa.free(inside_worktree);
    const allowed_term = try support.runProbe(gpa, &workspace, probe_root_tmp, "write", inside_worktree);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, allowed_term);
}
