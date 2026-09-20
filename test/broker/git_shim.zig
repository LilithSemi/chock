//! The honest half of the git shim on a running system. The shim prevents a
//! mistake and not an attack, so this takes the easiest way around it and
//! shows the capability layers still refuse the push.

const std = @import("std");
const chock_workspace = @import("chock-workspace");

const Workspace = chock_workspace.Workspace;
const testing = std.testing;

// The sandbox work runs through `escape_probe`, because `Sandbox.spawn` forks
// and the zig test runner is not a single threaded caller.
const support = @import("support.zig");

/// A listener on `127.0.0.1` that keeps the first bytes anybody sent it. It
/// answers at once so a git that did have a route gives up instead of hanging.
const Recorder = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    server: std.Io.net.Server,
    port: u16,
    thread: std.Thread,
    stop: std.atomic.Value(bool),
    seen: std.ArrayList(u8),

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
            // A connection that sends nothing ends this, as `finish` does.
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
    const gpa = testing.allocator;
    const io = testing.io;

    const git_path = (try support.findGitOnPath(gpa, io)) orelse {
        // A test that writes to standard error and passes still puts a `failed command:` line in the build log.
        return error.SkipZigTest;
    };
    defer gpa.free(git_path);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // `TestProject` sets `GIT_CEILING_DIRECTORIES`, because `tmpDir` puts every scratch repository under Chock's own checkout.
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

    // A write inside the worktree still works, so the refusals above are the network layer.
    const wt = workspace.kind.worktree;
    const inside_worktree = try std.fs.path.join(gpa, &.{ wt.project_root, "chock-shim-test.txt" });
    defer gpa.free(inside_worktree);
    const allowed_term = try support.runProbe(gpa, &workspace, probe_root_tmp, "write", inside_worktree);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, allowed_term);
}
