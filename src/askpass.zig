//! `chock askpass`: answer the password prompt `git` or `ssh` wrote.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_proto = @import("chock-proto");

const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const askpass = chock_broker.askpass;

pub const answer_timeout_ms: i32 = 10_000;

const usage_text =
    \\Usage: chock askpass <prompt>
    \\
    \\Answers one password prompt from git or ssh, out of the credentials the
    \\broker holds. git runs this itself through GIT_ASKPASS or core.askPass,
    \\and ssh runs it through SSH_ASKPASS. There is rarely a reason to run it
    \\by hand.
    \\
    \\It reads no credential store. It asks the session named by
    \\CHOCK_ASKPASS_SOCKET, which holds a path and never a credential, and the
    \\session's policy decides whether to answer and for which host. A prompt
    \\nobody permitted gets nothing, and this prints nothing.
    \\
;

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = exe_path;
    _ = gpa;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);
    defer env.deinit();

    const prompt = readArgs(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.NotOnePrompt => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const socket_path = env.get(askpass.env_socket) orelse {
        return refuse(.nobody_answered, "no session named " ++ askpass.env_socket);
    };

    const line = ask(arena, io, socket_path, prompt) catch |err| {
        return refuse(.nobody_answered, @errorName(err));
    };
    defer askpass.wipe(line);

    var parsed = std.json.parseFromSlice(askpass.Reply, arena, line, .{
        .ignore_unknown_fields = true,
    }) catch {
        return refuse(.nobody_answered, "the session said something this cannot read");
    };
    defer parsed.deinit();

    if (parsed.value.secret) |value| {
        try writeSecret(io, value);
        return Exit.finished.code();
    }

    const named = parsed.value.refused orelse "";
    const refusal = askpass.Refusal.fromWireName(named) orelse .nobody_answered;
    return refuse(refusal, named);
}

fn readArgs(args: []const []const u8) error{ HelpWanted, NotOnePrompt }![]const u8 {
    if (args.len == 1 and (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h"))) {
        return error.HelpWanted;
    }
    if (args.len != 1) return error.NotOnePrompt;
    return args[0];
}

fn ask(
    arena: std.mem.Allocator,
    io: std.Io,
    socket_path: []const u8,
    prompt: []const u8,
) ![]u8 {
    const address = try chock_proto.control.unixAddress(socket_path);
    const stream = try address.connect(io);
    defer stream.close(io);

    const line = try askpass.askLine(arena, prompt);
    defer arena.free(line);
    if (!chock_broker.socket.writeAll(stream.socket.handle, line)) return error.SessionWentAway;

    const buffer = try arena.alloc(u8, askpass.max_frame_bytes);
    errdefer {
        askpass.wipe(buffer);
        arena.free(buffer);
    }

    var filled: usize = 0;
    while (filled < buffer.len) {
        if (!chock_broker.socket.readable(stream.socket.handle, answer_timeout_ms)) {
            return error.SessionDidNotAnswer;
        }
        const read = try std.posix.read(stream.socket.handle, buffer[filled..]);
        if (read == 0) return error.SessionWentAway;
        filled += read;
        if (std.mem.indexOfScalar(u8, buffer[0..filled], '\n')) |end| return buffer[0..end];
    }
    return error.AnswerTooLong;
}

fn writeSecret(io: std.Io, value: []const u8) !void {
    // Not through tty.out: those writers can be tapped by a display, and this write must reach git and nowhere else.
    tty.flushOut();

    var buffer: [256]u8 = undefined;
    var file = std.Io.File.stdout().writer(io, &buffer);
    defer askpass.wipe(&buffer);
    try file.interface.writeAll(value);
    try file.interface.writeByte('\n');
    try file.interface.flush();
}

fn refuse(refusal: askpass.Refusal, detail: []const u8) u8 {
    tty.print(.err, "chock askpass: {s} ({s})\n", .{ refusal.text(), detail });
    return Exit.refused.code();
}

const testing = std.testing;

test "the command line is one prompt, and a prompt that looks like an option is still a prompt" {
    try testing.expectEqualStrings("Password for 'https://x': ", try readArgs(&.{"Password for 'https://x': "}));
    try testing.expectEqualStrings("--color=always", try readArgs(&.{"--color=always"}));
    try testing.expectEqualStrings("-h -h", try readArgs(&.{"-h -h"}));

    try testing.expectError(error.HelpWanted, readArgs(&.{"--help"}));
    try testing.expectError(error.HelpWanted, readArgs(&.{"-h"}));
    try testing.expectError(error.NotOnePrompt, readArgs(&.{}));
    try testing.expectError(error.NotOnePrompt, readArgs(&.{ "one", "two" }));
}

test "every refusal prints on standard error and nothing at all on standard output" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    for (std.enums.values(askpass.Refusal)) |refusal| {
        _ = refuse(refusal, "a detail");
    }

    try testing.expectEqualStrings("", said.out());
    try testing.expect(said.err().len != 0);
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock askpass") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "LC_ALL=C") != null);
}

// Until 2026-08-25 this path reached std.Io.net.UnixAddress.init unbounded, and a path of 105 to 108 bytes wrote past sun_path on Darwin.
test "the socket named by the environment is bounded before it is connected" {
    const bound = chock_proto.control.max_socket_path;
    var buffer: [256]u8 = undefined;

    const at_bound = buffer[0..bound];
    @memset(at_bound, 'a');
    at_bound[0] = '/';
    try testing.expectError(error.FileNotFound, ask(testing.allocator, testing.io, at_bound, "p"));

    const at_std = buffer[0..std.Io.net.UnixAddress.max_len];
    @memset(at_std, 'a');
    at_std[0] = '/';
    try testing.expectError(error.PathTooLong, ask(testing.allocator, testing.io, at_std, "p"));

    const over = buffer[0 .. bound + 1];
    @memset(over, 'a');
    over[0] = '/';
    try testing.expectError(error.PathTooLong, ask(testing.allocator, testing.io, over, "p"));
}

test "a refusal is not a crash, and it is not success either" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(Exit.refused.code(), refuse(.nobody_answered, ""));
    try testing.expect(Exit.refused.code() != Exit.finished.code());
    try testing.expect(Exit.refused.code() != Exit.faulted.code());

    try testing.expectEqualStrings("", said.out());
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock askpass") != null);
}
