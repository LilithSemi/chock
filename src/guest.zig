//! `chock guest`: what runs inside a microVM, one tool call at a time.
//!
//! **A subcommand and not a program of its own.** Chock installs one binary and
//! no helper beside it, which `test/plugin/one_binary.zig` pins. A guest's initrd
//! carries a Linux build of that one binary and runs `chock guest` in it, so the
//! program sandboxing a tool call inside a guest is the program that sandboxes
//! one outside.
//!
//! **A guest is a layer and not an alternative.** It has a kernel of its own, so
//! namespaces, seccomp, Landlock and cgroups all work in here, and this program
//! runs the very driver a Linux host runs. The boundary a tool call gets inside a
//! guest is the same boundary, built from the same `Config` and the same code.
//! Mirage's own design says a guest is root inside itself, which is exactly why
//! this still sandboxes.
//!
//! ## What it does, and what it deliberately does not
//!
//! It opens one stream to whoever started the guest, reads one request a line on
//! it, builds the `Config` that request describes, runs the driver, and answers.
//! That is all.
//!
//! * **It resolves no name and opens no socket.** A tool call that reaches the
//!   network gets a connected descriptor from the host, through Mirage's own
//!   `reaching` message. The host decides, resolves and connects, so a guest
//!   cannot ask for one host and be handed another.
//! * **It holds no policy.** Every question was answered on the host before a
//!   request was written. This program refuses a request it cannot build a
//!   `Config` from, and refuses nothing else.
//! * **It must not grow a copy of `addressIsReachable`.** That check runs on the
//!   host after a name resolves: see `lib/chock-broker/network.zig`.
//!
//! ## One thread, because the driver forks
//!
//! The driver forks, and a fork carries only the calling thread. So this program
//! is one thread and one loop, the same rule `lib/chock-core/tools.zig` states
//! for the host's tool path.

const std = @import("std");
const chock_sandbox = @import("chock-sandbox");

const linux = std.os.linux;

const tty = @import("tty.zig");

const wire = chock_sandbox.vm_wire;
const Sandbox = chock_sandbox.Sandbox;

/// The vsock port this connects to. `mirage_session.wire.control_port`, because
/// the host end asks for a stream on that port and nothing else routes here.
pub const default_port: u32 = 1024;

/// `VMADDR_CID_HOST`. Whoever started the guest is always at this address, and
/// there is no other address a guest can name.
const cid_host: u32 = 2;

/// Connect to whoever started this guest.
///
/// **A vsock and not a descriptor the init passed in.** A guest opens the
/// connection and the host takes it: that is the only direction Mirage's channel
/// runs, and an init made of busybox cannot open one.
fn dialHost(port: u32) DialError!std.posix.fd_t {
    // The raw calls, the way `lib/chock-sandbox/linux/driver.zig` reaches
    // `pidfd_send_signal`: `std.Io.net` has an address for IP and for a unix path
    // and none for a vsock, and a guest is Linux by construction.
    const made = linux.socket(linux.AF.VSOCK, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(made) != .SUCCESS) return error.NoSocket;
    const fd: std.posix.fd_t = @intCast(made);
    errdefer _ = linux.close(fd);

    const address = linux.sockaddr.vm{
        .port = port,
        .cid = cid_host,
        .flags = 0,
    };
    const joined = linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.vm));
    if (linux.errno(joined) != .SUCCESS) return error.NobodyThere;
    return fd;
}

pub const DialError = error{
    /// The kernel has no vsock at all, so this is not a guest of Mirage's.
    NoSocket,
    /// Nothing is listening on that port.
    NobodyThere,
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

    const port = portFrom(args) catch {
        tty.print(
            .err,
            "chock guest: this takes --port <number> and nothing else. It is started by a " ++
                "guest's own init, not by a person.\n",
            .{},
        );
        return 2;
    };

    const control = dialHost(port) catch |err| {
        // Nobody is listening, which means this is not a guest Chock started.
        tty.print(
            .err,
            "chock guest: nothing answered on vsock port {d} ({t}). This runs inside a " ++
                "microVM Chock started and nowhere else.\n",
            .{ port, err },
        );
        return 1;
    };
    defer _ = linux.close(control);

    const read_buffer = try gpa.alloc(u8, wire.max_message_bytes + 1);
    defer gpa.free(read_buffer);
    var write_buffer: [64 * 1024]u8 = undefined;

    // Blocking, because this loop has one thread and every read of it waits for
    // the host's next request.
    const stream = std.Io.File{ .handle = control, .flags = .{ .nonblocking = false } };
    var reader = stream.reader(io, read_buffer);
    var writer = stream.writer(io, &write_buffer);

    try serve(gpa, &reader.interface, &writer.interface);
    return 0;
}

/// The port `--port` named, or the default when nothing was said.
fn portFrom(args: []const []const u8) error{Unreadable}!u32 {
    if (args.len == 0) return default_port;
    if (args.len != 2) return error.Unreadable;
    if (!std.mem.eql(u8, args[0], "--port")) return error.Unreadable;
    return std.fmt.parseInt(u32, args[1], 10) catch error.Unreadable;
}

/// Answer requests until the stream ends. Split from `main` so a test can drive
/// it over a pair of pipes with no guest at all.
pub fn serve(
    gpa: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
) !void {
    while (true) {
        const parsed = wire.read(wire.Request, gpa, reader) catch |err| switch (err) {
            // The host let go, which is how a session ends.
            error.Ended => return,
            error.OutOfMemory => return error.OutOfMemory,
            // A line this build cannot read ends that request and not the
            // program: the next one may be readable.
            error.TooLong, error.Unreadable => {
                try wire.write(writer, wire.Answer{
                    .refusal = "the request could not be read by this build of chock-guest",
                });
                continue;
            },
        };
        defer parsed.deinit();

        try answer(gpa, writer, parsed.value);
    }
}

/// Run one request and write its answer.
fn answer(gpa: std.mem.Allocator, writer: *std.Io.Writer, request: wire.Request) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const config = wire.configFor(arena, request) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // The host asked for a trap this build cannot install. Refusing says so;
        // running the call anyway would give it a smaller trap set than the host
        // believes it asked for.
        error.UnknownTrap => return wire.write(writer, wire.Answer{
            .refusal = "the request named a syscall trap this build of chock-guest has no name for",
        }),
    };

    if (request.argv.len == 0) {
        return wire.write(writer, wire.Answer{
            .refusal = "the request named no program to run",
        });
    }

    // Zeroed rather than written out field by field: the driver fills this in,
    // and a feature added to `landlock.Features` must not have to be listed here
    // as well.
    var report: Sandbox.LandlockReport = std.mem.zeroes(Sandbox.LandlockReport);
    const term = Sandbox.spawn(arena, config, request.argv, &report, null) catch |err| {
        // The name of the fault and never a sentence built here: the host holds
        // the words, and two spellings of one fault is how a message drifts.
        const said = try std.fmt.allocPrint(arena, "the sandbox could not be built: {t}", .{err});
        return wire.write(writer, wire.Answer{ .refusal = said });
    };

    return wire.write(writer, wire.Answer{
        .ended = switch (term) {
            .exited => |code| .{ .exited = code },
            .signal => |sig| .{ .signalled = @intFromEnum(sig) },
            .stopped => |sig| .{ .stopped = @intFromEnum(sig) },
            .unknown => |code| .{ .unknown = code },
        },
        // The abi the guest's own kernel answered. A host reads it to know which
        // layers were really on inside, and a guest kernel with no Landlock at
        // all is a fact the host must be able to see.
        .landlock = .{ .applied = report.features.supported, .abi = report.abi },
    });
}

const testing = std.testing;

/// One request a line, as the host would write them.
fn script(buffer: []u8, requests: []const wire.Request) ![]const u8 {
    var writer = std.Io.Writer.fixed(buffer);
    for (requests) |one| try wire.write(&writer, one);
    return writer.buffered();
}

const nothing_to_run = wire.Request{
    .root = "/",
    .mounts = &.{},
    .rules = &.{},
    .cwd = "/",
    .env = &.{},
    .argv = &.{},
};

test "a request naming no program is refused, and the one after it is still read" {
    var in_buffer: [4096]u8 = undefined;
    const lines = try script(&in_buffer, &.{ nothing_to_run, nothing_to_run });

    var reader = std.Io.Reader.fixed(lines);
    var out_buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    try serve(testing.allocator, &reader, &writer);

    // Two answers, each a refusal, and the loop ended because the stream did.
    const said = writer.buffered();
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, said, "\n"));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, said, "named no program"));
    // A refusal carries no exit code: a guest that could not run a call must
    // never report one it did not see.
    try testing.expect(std.mem.indexOf(u8, said, "\"ended\":null") != null);
}

test "a line this build cannot read ends that request and not the program" {
    var in_buffer: [4096]u8 = undefined;
    const tail = try script(in_buffer[512..], &.{nothing_to_run});

    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(testing.allocator);
    try joined.appendSlice(testing.allocator, "{this is not a request}\n");
    try joined.appendSlice(testing.allocator, tail);

    var reader = std.Io.Reader.fixed(joined.items);
    var out_buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    try serve(testing.allocator, &reader, &writer);

    const said = writer.buffered();
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, said, "\n"));
    try testing.expect(std.mem.indexOf(u8, said, "could not be read") != null);
    try testing.expect(std.mem.indexOf(u8, said, "named no program") != null);
}

test "a stream that ends with nothing on it is not an error" {
    var reader = std.Io.Reader.fixed("");
    var out_buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    try serve(testing.allocator, &reader, &writer);
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "this program resolves nothing and holds no policy" {
    // Two properties the top comment states, read from the source so a later
    // change has to edit the comment as well.
    const own_source = @embedFile("guest.zig");
    for ([_][]const u8{
        "getAddressList",
        "addressIsReachable",
        "resolve",
        "chock-policy",
        "chock-broker",
    }) |name| {
        // The words appear in prose above, so this looks for the shapes a use
        // would have and not for the word itself.
        const called = try std.fmt.allocPrint(testing.allocator, "{s}(", .{name});
        defer testing.allocator.free(called);
        const imported = try std.fmt.allocPrint(testing.allocator, "@import(\"{s}\")", .{name});
        defer testing.allocator.free(imported);

        try testing.expect(std.mem.indexOf(u8, own_source, called) == null);
        try testing.expect(std.mem.indexOf(u8, own_source, imported) == null);
    }
}

test "the port comes from --port, and anything else is refused rather than guessed" {
    try testing.expectEqual(default_port, try portFrom(&.{}));
    try testing.expectEqual(@as(u32, 2048), try portFrom(&.{ "--port", "2048" }));

    // Each of these would otherwise be read as the default, and a guest that
    // dialled the wrong port would wait for a host that is not there.
    try testing.expectError(error.Unreadable, portFrom(&.{"2048"}));
    try testing.expectError(error.Unreadable, portFrom(&.{ "--port", "not-a-number" }));
    try testing.expectError(error.Unreadable, portFrom(&.{ "-p", "2048" }));
    try testing.expectError(error.Unreadable, portFrom(&.{ "--port", "1", "2" }));
}

/// A pair of connected streams, for a test that drives both halves of the wire.
fn pair() ![2]std.posix.fd_t {
    var fds: [2]i32 = undefined;
    const made = linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        0,
        &fds,
    );
    if (linux.errno(made) != .SUCCESS) return error.SkipZigTest;
    return fds;
}

test "the host driver and this program agree, over a real pair of streams" {
    const gpa = testing.allocator;
    const io = testing.io;

    const fds = try pair();
    const host_end = fds[0];
    const guest_end = fds[1];
    defer _ = linux.close(host_end);

    // The guest answers one request and its side of the pair ends, so `serve`
    // returns rather than waiting for a second. One thread throughout: the driver
    // forks, and a fork carries only the calling thread.
    const host = std.Io.File{ .handle = host_end, .flags = .{ .nonblocking = false } };

    var read_buffer: [8192]u8 = undefined;
    var write_buffer: [8192]u8 = undefined;
    // Only its share set is read here: the request is written by hand below so
    // this test needs no second thread to answer it.
    const guest = chock_sandbox.vm_driver.Guest{
        .stream = host,
        .io = io,
        .shares = .{
            .root = "/mnt/shares",
            .shares = &.{
                .{ .name = "store", .host_path = "/nix/store", .writable = false },
            },
        },
        .read_buffer = &read_buffer,
        .write_buffer = &write_buffer,
    };

    // A request the guest refuses before it would spawn anything: no program to
    // run. That keeps this test free of a fork while still crossing the wire in
    // both directions through the real code on each side.
    const config = Sandbox.Config{
        .root = "/sandbox",
        .mounts = &.{.{ .bind = .{
            .source = "/nix/store/aaa-jq",
            .target = "/nix/store/aaa-jq",
            .read_only = true,
        } }},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    };

    // The driver writes its request, then waits for an answer. So the guest is
    // served first, from the bytes already in the socket, and the driver reads
    // what it wrote back. Two passes and no thread.
    // An arena: `translate` allocates one string a path, which is what its own
    // doc comment says to hold this way.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var request_buffer: [8192]u8 = undefined;
    var writing = host.writer(io, &request_buffer);
    var share_fault: ?chock_sandbox.vm_shares.Fault = null;
    const moved = try chock_sandbox.vm_shares.translate(arena, config, guest.shares, &share_fault);
    const asked = (try wire.requestFor(arena, moved, &.{})).?;
    try wire.write(&writing.interface, asked);

    // The source the guest is told about is where the guest can reach it, and the
    // target is what a compiler message would print.
    try testing.expectEqualStrings("/mnt/shares/store/aaa-jq", asked.mounts[0].bind.source);
    try testing.expectEqualStrings("/nix/store/aaa-jq", asked.mounts[0].bind.target);

    const guest_stream = std.Io.File{ .handle = guest_end, .flags = .{ .nonblocking = false } };
    var guest_read: [8192]u8 = undefined;
    var guest_write: [8192]u8 = undefined;
    var guest_reader = guest_stream.reader(io, &guest_read);
    var guest_writer = guest_stream.writer(io, &guest_write);

    // The host end stops writing, so the guest sees the stream end after one
    // request and `serve` comes back.
    _ = linux.shutdown(host_end, linux.SHUT.WR);
    try serve(gpa, &guest_reader.interface, &guest_writer.interface);
    _ = linux.close(guest_end);

    // And the answer the guest wrote is one this build reads: a refusal naming
    // the reason, with no exit code invented for a call that never ran.
    var answer_buffer: [8192]u8 = undefined;
    var answer_reader = host.reader(io, &answer_buffer);
    const said = try wire.read(wire.Answer, gpa, &answer_reader.interface);
    defer said.deinit();
    try testing.expectEqual(@as(?wire.Answer.Ended, null), said.value.ended);
    try testing.expect(std.mem.indexOf(u8, said.value.refusal.?, "named no program") != null);
}
