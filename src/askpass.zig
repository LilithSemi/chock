//! `chock askpass`: answer the password prompt `git` or `ssh` wrote.
//!
//! ```
//! GIT_ASKPASS=$(command -v chock) git push
//! ```
//!
//! **This is the client half of the askpass helper**, and
//! `lib/chock-broker/askpass.zig` is the half that holds the credentials and
//! decides. Read that file's own top comment first. It says the thing a reader
//! of this one has to know: the helper prevents a mistake and it does not
//! prevent an attack, the capability layers are the boundary, and an agent can
//! bypass this program with three lines of its own.
//!
//! ## What this program does, in full
//!
//! `git` runs it with the prompt as one argument, and reads standard output.
//! So it:
//!
//! 1. reads the one argument;
//! 2. connects to the socket named by `chock_broker.askpass.env_socket`;
//! 3. sends the prompt, unread and unchanged;
//! 4. reads one line back;
//! 5. writes the value to standard output, or writes nothing at all.
//!
//! **It reads no credential store and it holds no decision.** That is not a
//! shortcut. The store is never mounted into a sandbox, so a helper that read
//! one would work outside a sandbox and fail inside it for a reason nobody
//! could see. Asking the broker works the same way in both places, and inside a
//! sandbox it fails at the connect, which is the honest failure and the safe
//! one.
//!
//! ## The value never goes through the terminal writers
//!
//! `src/tty.zig` holds the two writers this program prints through, and a
//! display can tap them: `tty.Capture` turns every line into a row of a
//! transcript. So the value is written straight to standard output, through a
//! writer this file makes for that one write and flushes at once. Everything
//! else this program says, including every refusal, goes to standard error
//! through `tty.print`, where it can be read by a person and cannot be
//! mistaken for the answer.
//!
//! ## Nobody to ask is a refusal, and a refusal prints nothing
//!
//! There is no reply, or the reply refuses, or the socket is not there at all,
//! which is what a tool call inside the sandbox always gets. In every one of
//! those this program writes **nothing** to standard output and exits
//! `Exit.refused`.
//!
//! Measured against git 2.55: a helper that prints nothing makes `git` say
//! `unable to read askpass response`, and then `could not read Password for
//! ...`, and fail. That is the whole of the safe direction reaching `git`: an
//! approval nobody answered is a no, and the act does not happen.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_proto = @import("chock-proto");

const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const askpass = chock_broker.askpass;

/// How long this waits for the session to answer.
///
/// **Short, because `git` is holding still for it and the answer is already
/// decided.** The broker asks nobody: see `lib/chock-broker/askpass.zig`. So
/// the only thing this budget covers is one round trip on a unix socket, and a
/// session that has not answered in this long is one that is not polling its
/// endpoint.
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

    // **A path, and this is the only variable in the design.** See
    // `lib/chock-broker/askpass.zig`: a credential never travels in the
    // environment and never on a command line.
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

/// The one prompt `git` passed. Everything else is a command line nobody meant
/// to write.
///
/// **Exactly one argument, and `--help` is the only word read out of it.** A
/// prompt is untrusted text and it is not searched for options: a remote whose
/// URL made the prompt start with a dash must not be able to make this program
/// do something else. `main.zig` has already taken the global options off the
/// line before this runs.
fn readArgs(args: []const []const u8) error{ HelpWanted, NotOnePrompt }![]const u8 {
    if (args.len == 1 and (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h"))) {
        return error.HelpWanted;
    }
    if (args.len != 1) return error.NotOnePrompt;
    return args[0];
}

/// Connect, send the prompt, and read one line back. The caller owns the line
/// and wipes it.
///
/// **The path is bounded before it is connected.** It arrives from
/// `CHOCK_ASKPASS_SOCKET`, and `std` copies it into `sun_path` on this end as
/// well as on the listening one: a path past that field ends a safety checked
/// build inside `connect` and writes past the field in a release one. See
/// `chock-proto/control.zig`'s `max_socket_path`.
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

/// Write the value, and nothing else, to standard output.
///
/// **Not through `tty.out`.** See this file's own top comment: those writers
/// can be tapped by a display, and this one write must reach `git` and nowhere
/// else. The trailing line break is what `git` and `ssh` both strip, and both
/// accept a value with none, so it costs nothing and it makes the output a
/// line when a person runs this by hand.
fn writeSecret(io: std.Io, value: []const u8) !void {
    // **Whatever `tty` is holding for standard output goes first.** Nothing on
    // this path writes there, so this sends nothing, and it means the one
    // write below can never land in front of bytes another call already
    // buffered on the same descriptor.
    tty.flushOut();

    var buffer: [256]u8 = undefined;
    var file = std.Io.File.stdout().writer(io, &buffer);
    defer askpass.wipe(&buffer);
    try file.interface.writeAll(value);
    try file.interface.writeByte('\n');
    try file.interface.flush();
}

/// Say why, on standard error, and give back the code a script reads.
///
/// **Nothing reaches standard output on this path.** `git` reads standard
/// output and standard output alone, so a refusal that printed there would be
/// a password as far as `git` is concerned.
/// One line and not two, because this lands in `git`'s own standard error
/// beside `git`'s own message about the same failure.
fn refuse(refusal: askpass.Refusal, detail: []const u8) u8 {
    tty.print(.err, "chock askpass: {s} ({s})\n", .{ refusal.text(), detail });
    return Exit.refused.code();
}

const testing = std.testing;

test "the command line is one prompt, and a prompt that looks like an option is still a prompt" {
    // A remote URL is a file in the agent's own workspace, so the prompt is
    // untrusted text. A reader that searched it for options would let a
    // crafted remote change what this program does.
    try testing.expectEqualStrings("Password for 'https://x': ", try readArgs(&.{"Password for 'https://x': "}));
    try testing.expectEqualStrings("--color=always", try readArgs(&.{"--color=always"}));
    try testing.expectEqualStrings("-h -h", try readArgs(&.{"-h -h"}));

    try testing.expectError(error.HelpWanted, readArgs(&.{"--help"}));
    try testing.expectError(error.HelpWanted, readArgs(&.{"-h"}));
    try testing.expectError(error.NotOnePrompt, readArgs(&.{}));
    try testing.expectError(error.NotOnePrompt, readArgs(&.{ "one", "two" }));
}

test "every refusal prints on standard error and nothing at all on standard output" {
    // The fault this pins: `git` reads standard output and nothing else, so
    // one line of explanation printed there would be read as the password.
    //
    // Mutation check: change `tty.print` to `tty.out` in `refuse` and the
    // first expectation below fails.
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    for (std.enums.values(askpass.Refusal)) |refusal| {
        _ = refuse(refusal, "a detail");
    }

    try testing.expectEqualStrings("", said.out());
    try testing.expect(said.err().len != 0);
    // And each refusal said which one it was, in words a person can act on.
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock askpass") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "LC_ALL=C") != null);
}

test "the socket named by the environment is bounded before it is connected" {
    // **`CHOCK_ASKPASS_SOCKET` is where a path enters this program**, and until
    // 2026-08-25 `ask` handed it to `std.Io.net.UnixAddress.init`, whose only
    // bound is a flat 108 on every platform that is not Windows. Darwin's
    // `sun_path` is 104 bytes, so a path of 105 to 108 passed that call and then
    // reached an `@memcpy` past the end of the field inside `connect`, which
    // ends a safety checked build and writes past the field in a release one.
    //
    // Mutation check: put `std.Io.net.UnixAddress.init` back. On Darwin the
    // middle third ends the whole test binary inside `connect`, which is the
    // fault itself. On Linux it reports the wrong refusal instead, because
    // `std` connects an unterminated 108 there quite happily.
    //
    // No path here exists, and none needs to: the copy into `sun_path` happens
    // before the system call.
    const bound = chock_proto.control.max_socket_path;
    var buffer: [256]u8 = undefined;

    // A refusal by length would hide the fault rather than close it, so the
    // bound itself has to reach `connect` and fail there for want of a socket.
    const at_bound = buffer[0..bound];
    @memset(at_bound, 'a');
    at_bound[0] = '/';
    try testing.expectError(error.FileNotFound, ask(testing.allocator, testing.io, at_bound, "p"));

    // **The longest path `std` itself takes, named on purpose and asked first.**
    // On Linux it is one byte past the bound and on Darwin it is five, and five
    // is where the copy runs off the end of `sun_path`. Put after the line
    // below, this assertion would never be reached under the mutation, because
    // Darwin's `sun_path` swallows a path of exactly 104 without complaint.
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
    // An approval nobody answered is a refusal, and a script must be able to
    // tell that from a fault. `Exit.refused` is the code that already says so
    // for a whole session.
    //
    // **The capture is what keeps the build log honest.** `refuse` writes on
    // standard error on purpose, and a command function called with no streams
    // set falls back to the real one: see `src/tty.zig`. `zig build` then
    // prints a `failed command:` line for a run step that wrote there whatever
    // its exit status, so this passing test read in the log as a failure. See
    // `test/proto/lock.zig`, which holds the rule.
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(Exit.refused.code(), refuse(.nobody_answered, ""));
    try testing.expect(Exit.refused.code() != Exit.finished.code());
    try testing.expect(Exit.refused.code() != Exit.faulted.code());

    // Captured and not silenced. A refusal that said nothing at all would pass
    // the three expectations above and leave `git`'s own failure unexplained.
    try testing.expectEqualStrings("", said.out());
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock askpass") != null);
}
