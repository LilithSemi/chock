//! `chock approve`: answer a question a running session is asking.
//!
//! ```
//! chock approve             # attach to the newest session of this project
//! chock approve <session>   # attach to that one
//! ```
//!
//! **This is the client half of the approval socket.** A session that has
//! nobody at its own keyboard, which is every session `chock daemon` started
//! and every subagent, could not be asked anything at all: `Loop.run` holds the
//! exclusive lock on the session log, so no answer could be appended by anybody
//! else. `lib/chock-broker/socket.zig` is the session's end of the answer, and
//! this is the person's end of it.
//!
//! ## It holds no lock, and it writes nothing
//!
//! The session owns its log and keeps owning it. This connects, reads the
//! question the session sends, shows it, reads a word, and sends a decision
//! back. **The session is what appends the `approval.response`**, through the
//! handle it already holds. That is the whole reason the broker does not have
//! to own the log, and `lib/chock-broker/socket.zig`'s own top comment says it
//! at length.
//!
//! ## What is shown, and why it is filtered
//!
//! Exactly what `chock run` shows a person at its own terminal:
//! `approval.promptText` builds it and `approval.writeFiltered` writes it. The
//! detail of a request is a diff the agent wrote, so an escape sequence in a
//! file it changed could otherwise repaint the question being answered. One
//! function for both paths, because a second copy of that filter is a second
//! thing that can be forgotten.
//!
//! ## What this is not
//!
//! It is not `chock daemon`'s protocol and it does not read the log. A client
//! that wants to watch a session reads the log, which `chock daemon` already
//! serves. This answers one question at a time and nothing else, which is the
//! `approve` scope and none of the others.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_proto = @import("chock-proto");

const approval = @import("approval.zig");
const session_paths = @import("session.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const event = chock_proto.event;

/// The longest question this reads off the socket. The session bounds what it
/// sends by `chock_broker.socket` and by the size of a diff, and this bounds
/// what a client will hold for something that claims to be a session.
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
        // A session that has ended removed its socket, and one that never had
        // one never made it. Neither is a fault of this command.
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

/// Read questions and answer them until the session goes away.
///
/// **The session ending is the ordinary way this stops**, not an error: the
/// socket closes with it and the read comes back with the end of the stream.
fn serve(gpa: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream) anyerror!u8 {
    const stdin = approval.Stdin{};
    const console = stdin.console();

    var buffer = try gpa.alloc(u8, max_question_bytes);
    defer gpa.free(buffer);
    var filled: usize = 0;

    while (true) {
        const read = std.posix.read(stream.socket.handle, buffer[filled..]) catch |err| switch (err) {
            // **A session ending is the ordinary way this stops.** A process
            // that exits closes its end, and which of the two a client sees
            // depends on whether the kernel had anything left in the buffer: a
            // clean close reads as no bytes, and a process that went away reads
            // as a reset. Measured, on a real run, and treated the same because
            // they are the same fact.
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
        // Whatever came after the line break is the start of the next question.
        const rest = filled - (end + 1);
        std.mem.copyForwards(u8, buffer[0..rest], buffer[end + 1 .. filled]);
        filled = rest;

        const decided = answerOne(gpa, io, console, stream, line) catch |err| {
            tty.print(.err, "chock approve: that question could not be answered: {t}\n", .{err});
            return Exit.faulted.code();
        };
        if (!decided) {
            // A frame this build cannot read. Saying so and carrying on is
            // right: a newer session may send something this client has no case
            // for, and leaving would strand a question it could still answer.
            tty.print(.err, "chock approve: the session sent something this build cannot read.\n", .{});
        }
    }
}

/// Show one question and send back what was typed. False for a frame this
/// build has no case for.
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

    // **`.socket`, never `.terminal`.** This client is a peer of the approval
    // socket, and `lib/chock-broker/socket.zig`'s own clamp turns a session
    // grant claimed from any peer into a refusal. Printing the terminal's
    // `[y/N/s]` here would show a person a letter this connection can never
    // keep: see `approval.Client`'s own doc comment.
    const text = try approval.promptText(gpa, parsed.value.event.approval_request, .socket);
    defer gpa.free(text);
    // The same filter `chock run` writes its own prompt through. See this
    // file's own top comment.
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
                // **Left empty on purpose.** The session stamps the responder from
                // the peer credentials the kernel gave it, so a name written here
                // would be a name nobody checked: see
                // `lib/chock-broker/socket.zig`.
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

/// Read one line and say whether it is plainly yes.
///
/// **Anything that is not is a refusal**, and the end of the input is one too:
/// a person who walked away has not said yes. `approval.saysYes` is the one
/// place that reading lives, shared with `chock run` so the two cannot start
/// disagreeing about what a word means.
fn readWord(io: std.Io, console: approval.Console) !bool {
    var typed: [approval.max_answer_bytes]u8 = undefined;
    var filled: usize = 0;
    while (filled < typed.len) {
        switch (console.read(io, typed[filled..], std.time.ms_per_hour)) {
            // Nothing was typed for a very long time. Ask again rather than
            // decide for the person: the session has a deadline of its own and
            // it is the one that ends the question.
            .idle => continue,
            .canceled, .ended => return false,
            .bytes => |count| {
                filled += count;
                const end = std.mem.indexOfScalar(u8, typed[0..filled], '\n') orelse continue;
                return approval.saysYes(typed[0..end]);
            },
        }
    }
    // A line longer than the buffer is not one of the two words the prompt
    // named, so it is not an approval.
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

/// The newest session of this project, by name. A session identifier is a
/// ULID, so the newest one sorts last: see `session.newId`.
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

/// The same resolution `src/plan.zig` does, and for the same reason: a session
/// directory is keyed on the project's real path, so two names for one
/// directory must not be two projects.
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

/// A `Console` a test scripts, never a terminal. What `readWord` reads is the
/// only thing pinned here, so this needs none of `src/approval.zig`'s own
/// `FakeConsole` fields for a display or a budget.
const FakeConsole = struct {
    /// The lines `read` delivers, in order. Once they run out, the console
    /// reads as ended, the same as a person who walked away.
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

test "the session letter, typed here out of habit, is a plain refusal and never a grant" {
    // `promptText` no longer prints `s` as a choice for this client (see
    // `approval.zig`'s own test for that), but a person who typed it anyway,
    // remembering the terminal's prompt, must still land on the safe answer.
    // `readWord` knows one word, a plain yes, and everything else, `s`
    // included, is a no: there is no path here that could turn it into
    // `approved_by_user_for_session`, because this function returns a `bool`
    // and `answerOne` maps only `true` to `approved_by_user`.
    const io = testing.io;
    var console = FakeConsole{ .lines = &.{"s\n"} };
    try testing.expect(!(try readWord(io, console.console())));

    // The same is true of the word this build actually accepts nowhere but
    // the terminal.
    var session_word = FakeConsole{ .lines = &.{"session\n"} };
    try testing.expect(!(try readWord(io, session_word.console())));

    // A plain yes is still a yes, so this is not `readWord` refusing
    // everything.
    var yes = FakeConsole{ .lines = &.{"y\n"} };
    try testing.expect(try readWord(io, yes.console()));
}

test "the command line names one session at most" {
    // A second positional is a person who meant something else, and guessing
    // which of the two they meant is worse than saying so.
    try testing.expectEqualStrings("", (try parseOptions(&.{})).session);
    try testing.expectEqualStrings("01ABC", (try parseOptions(&.{"01ABC"})).session);
    try testing.expectEqualStrings("/tmp/p", (try parseOptions(&.{ "--project", "/tmp/p" })).project.?);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "01ABC", "01DEF" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--nope"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

test "a client sends the decision and never a responder it made up" {
    // The session stamps the responder from the peer credentials the kernel
    // gave it, and a client that wrote one would be writing a name nobody
    // checked into a security record. What is pinned is that the frame this
    // client builds carries the decision and the request it answers, and no
    // claim about who is answering.
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
    // And it is one line, because that is how the session reads it.
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, text, "\n"));
}
