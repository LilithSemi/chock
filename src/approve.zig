//! `chock approve`: answer a question a running session is asking.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_proto = @import("chock-proto");

const approval = @import("approval.zig");
const session_paths = @import("session.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const event = chock_proto.event;

pub const max_question_bytes: usize = 4 * 1024 * 1024;

const usage_text =
    \\Usage: chock approve [<session>] [options]
    \\
    \\Attaches to a running session and answers the questions it asks. With no
    \\session, attaches to the newest one of this project.
    \\
    \\A session only asks while it is running. Attaching to one that has ended
    \\says so and exits.
    \\
    \\Options:
    \\  --project <dir>   The project. Defaults to the current directory.
    \\
++ tty.options_text;

const Options = struct {
    project: ?[]const u8 = null,
    session: []const u8 = "",
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);
    defer env.deinit();

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const project_root = resolveProject(arena, io, options.project) catch {
        tty.print(.err, "chock approve: the project directory could not be read.\n", .{});
        return Exit.usage.code();
    };
    const dir = session_paths.projectDir(arena, &env, project_root) catch |err| {
        tty.print(.err, "chock approve: the session directory is unknown: {t}\n", .{err});
        return Exit.usage.code();
    };

    const id = if (options.session.len != 0) options.session else newestSession(arena, io, dir) orelse {
        tty.print(.err, "chock approve: this project has no session to attach to.\n", .{});
        return Exit.usage.code();
    };
    if (!session_paths.isValidId(id)) {
        tty.print(.err, "chock approve: {s} is not a session identifier.\n", .{id});
        return Exit.usage.code();
    }

    const paths = chock_broker.socket.pathsFor(arena, dir, id) catch return Exit.faulted.code();
    const address = chock_proto.control.unixAddress(paths.socket) catch {
        tty.print(
            .err,
            "chock approve: the path {s} is {d} bytes, and a unix socket path on this " ++
                "platform is at most {d}. The session opened no approval socket either, so " ++
                "give Chock a shorter state directory.\n",
            .{ paths.socket, paths.socket.len, chock_proto.control.max_socket_path },
        );
        return Exit.faulted.code();
    };
    const stream = address.connect(io) catch |err| {
        tty.print(
            .err,
            "chock approve: session {s} is not listening for answers ({t}). It has either " ++
                "ended or was started without an approval socket.\n",
            .{ id, err },
        );
        return Exit.usage.code();
    };
    defer stream.close(io);

    tty.print(.plain, "chock approve: attached to session {s}. Ctrl-C to leave.\n", .{id});
    return serve(gpa, io, stream);
}

fn serve(gpa: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream) anyerror!u8 {
    const stdin = approval.Stdin{};
    const console = stdin.console();

    var buffer = try gpa.alloc(u8, max_question_bytes);
    defer gpa.free(buffer);
    var filled: usize = 0;

    while (true) {
        const read = std.posix.read(stream.socket.handle, buffer[filled..]) catch |err| switch (err) {
            // A session ending reads as a reset when the kernel had nothing
            // left buffered, and as a clean zero-byte read otherwise. Both
            // mean the same thing here.
            error.ConnectionResetByPeer => {
                tty.print(.warn, "chock approve: the session has ended.\n", .{});
                return Exit.finished.code();
            },
            else => {
                tty.print(.err, "chock approve: the session could not be read: {t}\n", .{err});
                return Exit.faulted.code();
            },
        };
        if (read == 0) {
            tty.print(.warn, "chock approve: the session has ended.\n", .{});
            return Exit.finished.code();
        }
        filled += read;

        const end = std.mem.indexOfScalar(u8, buffer[0..filled], '\n') orelse {
            if (filled == buffer.len) {
                tty.print(.err, "chock approve: the session sent more than one question's worth of bytes.\n", .{});
                return Exit.faulted.code();
            }
            continue;
        };
        const line = buffer[0..end];
        const rest = filled - (end + 1);
        std.mem.copyForwards(u8, buffer[0..rest], buffer[end + 1 .. filled]);
        filled = rest;

        const decided = answerOne(gpa, io, console, stream, line) catch |err| {
            tty.print(.err, "chock approve: that question could not be answered: {t}\n", .{err});
            return Exit.faulted.code();
        };
        if (!decided) {
            tty.print(.err, "chock approve: the session sent something this build cannot read.\n", .{});
        }
    }
}

fn answerOne(
    gpa: std.mem.Allocator,
    io: std.Io,
    console: approval.Console,
    stream: std.Io.net.Stream,
    line: []const u8,
) !bool {
    var parsed = event.fromJson(gpa, line) catch return false;
    defer parsed.deinit();
    if (parsed.value.event != .approval_request) return false;

    const text = try approval.promptText(gpa, parsed.value.event.approval_request, .socket);
    defer gpa.free(text);
    approval.writeFiltered(console, io, text);

    const decision: event.ApprovalDecision = if (try readWord(io, console))
        .approved_by_user
    else
        .refused_by_user;

    const answer = try event.toJson(gpa, .{
        .id = 0,
        .session = parsed.value.session,
        .time_ms = std.Io.Timestamp.now(io, .real).toMilliseconds(),
        .event = .{
            .approval_response = .{
                .request_id = parsed.value.id,
                .decision = decision,
                // Left empty on purpose: the session stamps the responder
                // from its own peer credentials, not from a name this client sends.
                .responder = "",
            },
        },
    });
    defer gpa.free(answer);

    try writeAll(stream.socket.handle, answer);
    try writeAll(stream.socket.handle, "\n");
    console.write(io, if (decision == .approved_by_user) "\nallowed.\n" else "\nrefused.\n");
    return true;
}

fn readWord(io: std.Io, console: approval.Console) !bool {
    var typed: [approval.max_answer_bytes]u8 = undefined;
    var filled: usize = 0;
    while (filled < typed.len) {
        switch (console.read(io, typed[filled..], std.time.ms_per_hour)) {
            .idle => continue,
            .canceled, .ended => return false,
            .bytes => |count| {
                filled += count;
                const end = std.mem.indexOfScalar(u8, typed[0..filled], '\n') orelse continue;
                return approval.saysYes(typed[0..end]);
            },
        }
    }
    return false;
}

fn writeAll(handle: std.posix.fd_t, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = std.posix.system.write(handle, bytes.ptr + sent, bytes.len - sent);
        const written: isize = @bitCast(@as(usize, @bitCast(rc)));
        if (written > 0) {
            sent += @intCast(written);
            continue;
        }
        switch (std.posix.errno(rc)) {
            .INTR => continue,
            else => return error.SessionWentAway,
        }
    }
}

fn newestSession(arena: std.mem.Allocator, io: std.Io, dir: []const u8) ?[]const u8 {
    var opened = std.Io.Dir.openDirAbsolute(io, dir, .{ .iterate = true }) catch return null;
    defer opened.close(io);

    var newest: ?[]const u8 = null;
    var walker = opened.iterate();
    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .directory) continue;
        if (!std.mem.endsWith(u8, entry.name, chock_broker.socket.dir_suffix)) continue;
        const id = entry.name[0 .. entry.name.len - chock_broker.socket.dir_suffix.len];
        if (!session_paths.isValidId(id)) continue;
        if (newest) |held| {
            if (std.mem.order(u8, id, held) != .gt) continue;
        }
        newest = arena.dupe(u8, id) catch return null;
    }
    return newest;
}

fn resolveProject(arena: std.mem.Allocator, io: std.Io, given: ?[]const u8) ![]const u8 {
    if (given) |path| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return arena.dupe(u8, path);
        defer dir.close(io);
        const len = dir.realPath(io, &buffer) catch return arena.dupe(u8, path);
        return arena.dupe(u8, buffer[0..len]);
    }
    return std.process.currentPathAlloc(io, arena);
}

fn parseOptions(args: []const []const u8) !Options {
    var options = Options{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, arg, "--project")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.project = args[index];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return error.BadArguments;
        if (options.session.len != 0) return error.BadArguments;
        options.session = arg;
    }
    return options;
}

const testing = std.testing;

const FakeConsole = struct {
    lines: []const []const u8,
    taken: usize = 0,

    fn console(self: *FakeConsole) approval.Console {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = approval.Console.VTable{ .write = writeFn, .read = readFn };

    fn writeFn(ptr: *anyopaque, io: std.Io, bytes: []const u8) void {
        _ = ptr;
        _ = io;
        _ = bytes;
    }

    fn readFn(ptr: *anyopaque, io: std.Io, buffer: []u8, budget_ms: u64) approval.Console.Read {
        _ = io;
        _ = budget_ms;
        const self: *FakeConsole = @ptrCast(@alignCast(ptr));
        if (self.taken >= self.lines.len) return .ended;
        const line = self.lines[self.taken];
        self.taken += 1;
        std.debug.assert(line.len <= buffer.len);
        @memcpy(buffer[0..line.len], line);
        return .{ .bytes = line.len };
    }
};

test "the always letter, typed here out of habit, is a plain refusal and never a grant" {
    const io = testing.io;
    var console = FakeConsole{ .lines = &.{"a\n"} };
    try testing.expect(!(try readWord(io, console.console())));

    var always_word = FakeConsole{ .lines = &.{"always\n"} };
    try testing.expect(!(try readWord(io, always_word.console())));

    var old_letter = FakeConsole{ .lines = &.{"s\n"} };
    try testing.expect(!(try readWord(io, old_letter.console())));

    var yes = FakeConsole{ .lines = &.{"y\n"} };
    try testing.expect(try readWord(io, yes.console()));
}

test "the command line names one session at most" {
    try testing.expectEqualStrings("", (try parseOptions(&.{})).session);
    try testing.expectEqualStrings("01ABC", (try parseOptions(&.{"01ABC"})).session);
    try testing.expectEqualStrings("/tmp/p", (try parseOptions(&.{ "--project", "/tmp/p" })).project.?);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "01ABC", "01DEF" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--nope"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

test "a client sends the decision and never a responder it made up" {
    const gpa = testing.allocator;

    const text = try event.toJson(gpa, .{
        .id = 0,
        .session = "01APPROVE",
        .time_ms = 0,
        .event = .{ .approval_response = .{
            .request_id = 4096,
            .decision = .approved_by_user,
            .responder = "",
        } },
    });
    defer gpa.free(text);

    var parsed = try event.fromJson(gpa, text);
    defer parsed.deinit();
    const answer = parsed.value.event.approval_response;
    try testing.expectEqual(@as(u64, 4096), answer.request_id);
    try testing.expectEqualStrings("approved_by_user", answer.decision.wireName());
    try testing.expectEqualStrings("", answer.responder);
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, text, "\n"));
}
