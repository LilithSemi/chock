//! `chock guest`: what runs inside a microVM, one tool call at a time.

const std = @import("std");
const builtin = @import("builtin");
const chock_sandbox = @import("chock-sandbox");

const linux = std.os.linux;

const is_linux = builtin.os.tag == .linux;

const tty = @import("tty.zig");

const wire = chock_sandbox.vm_wire;
const Sandbox = chock_sandbox.Sandbox;

pub const default_port: u32 = 1024;

const cid_host: u32 = 2;

fn dialHost(port: u32) DialError!std.posix.fd_t {
    if (!is_linux) return error.NoSocket;

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
    NoSocket,
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

    if (!is_linux) {
        tty.print(
            .err,
            "chock guest: this runs inside a Linux guest and this build is {t}. A guest's own " ++
                "init starts it, and nothing else does.\n",
            .{builtin.os.tag},
        );
        return 1;
    }

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

    const read_buffer = try gpa.alloc(u8, wire.max_message_bytes + 1);
    defer gpa.free(read_buffer);

    // One turn is one connection. `chock run` is started for each turn and opens
    // its own channel, so this dials again and waits rather than ending: the
    // guest belongs to the session, not to the turn.
    var first = true;
    while (true) {
        const control = dialHost(port) catch |err| switch (err) {
            error.NobodyThere => {
                if (first) {
                    tty.print(
                        .err,
                        "chock guest: nothing answered on vsock port {d}. This runs inside a " ++
                            "microVM Chock started and nowhere else.\n",
                        .{port},
                    );
                    return powerOff(1);
                }
                // Between turns nothing is listening, which is the ordinary
                // case. The host ends this machine when the session is done.
                sleepMs(between_turns_ms);
                continue;
            },
            error.NoSocket => {
                tty.print(.err, "chock guest: this build has no vsock ({t}).\n", .{err});
                return powerOff(1);
            },
        };
        first = false;
        serveOne(gpa, io, control, read_buffer) catch |err| {
            tty.print(.err, "chock guest: the turn ended badly: {t}\n", .{err});
            _ = linux.close(control);
            return powerOff(1);
        };
        _ = linux.close(control);
    }
}

/// How long to wait before dialling again. Nothing listens between turns, so
/// this is the cost of noticing the next one starting.
const between_turns_ms: i32 = 50;

/// Stop the machine rather than return.
///
/// This process is the guest's init. A kernel panics when its init exits, whole
/// or not, so the machine is powered off here and the host reads the exit code
/// off the process it started instead.
fn powerOff(code: u8) u8 {
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
    // Only reached where this is not init, which is every test.
    return code;
}

/// Answer one turn on one connection.
fn serveOne(
    gpa: std.mem.Allocator,
    io: std.Io,
    control: std.posix.fd_t,
    read_buffer: []u8,
) !void {
    var write_buffer: [64 * 1024]u8 = undefined;

    const stream = std.Io.File{ .handle = control, .flags = .{ .nonblocking = false } };
    var reader = stream.readerStreaming(io, read_buffer);
    var writer = stream.writerStreaming(io, &write_buffer);

    // Before anything else on this stream: the host waits for it to know this is listening.
    writer.interface.writeAll(wire.hello_line) catch {};
    writer.interface.flush() catch {};

    var watch = Watch{ .fd = control, .io = io };
    const watcher = std.Thread.spawn(.{}, Watch.run, .{&watch}) catch null;
    defer if (watcher) |one| {
        watch.done.store(true, .release);
        one.join();
    };

    try serve(gpa, io, &reader.interface, &writer.interface, if (watcher == null) null else &watch);
}

const Watch = struct {
    fd: std.posix.fd_t,
    io: std.Io,
    middle: Sandbox.Middle = .{},
    armed: std.atomic.Value(bool) = .init(false),
    done: std.atomic.Value(bool) = .init(false),
    reading: std.Io.Mutex = .init,

    const wait_for_fork_ms: u32 = 1000;
    const poll_ms: i32 = 20;

    fn run(self: *Watch) void {
        var watching = [1]std.posix.pollfd{.{
            .fd = self.fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        var line: [64]u8 = undefined;

        while (!self.done.load(.acquire)) {
            if (!self.armed.load(.acquire)) {
                sleepMs(poll_ms);
                continue;
            }
            // Polled without the lock, which the resolver needs to send a name.
            const ready = std.posix.poll(&watching, poll_ms) catch continue;
            if (ready == 0) continue;

            self.reading.lockUncancelable(self.io);
            defer self.reading.unlock(self.io);
            if (!self.armed.load(.acquire)) continue;

            // Peeked rather than read: what is waiting could be the next request
            // instead of a cancel, and reading it would swallow that request.
            const seen = linux.recvfrom(
                self.fd,
                &line,
                line.len,
                linux.MSG.PEEK | linux.MSG.DONTWAIT,
                null,
                null,
            );
            if (linux.errno(seen) != .SUCCESS) continue;
            const cancel = wire.cancelAtStart(line[0..seen]) orelse continue;

            var taken: usize = 0;
            while (taken < cancel.bytes) {
                const got = linux.read(self.fd, line[taken..].ptr, cancel.bytes - taken);
                if (linux.errno(got) != .SUCCESS or got == 0) break;
                taken += got;
            }
            self.deliver(@enumFromInt(cancel.signal));
        }
    }

    fn deliver(self: *Watch, sig: std.posix.SIG) void {
        var waited: u32 = 0;
        while (waited < wait_for_fork_ms) : (waited += @intCast(poll_ms)) {
            if (!self.armed.load(.acquire)) return;
            if (@atomicLoad(std.posix.pid_t, &self.middle.pid, .acquire) != 0) break;
            sleepMs(poll_ms);
        }
        Sandbox.signalMiddle(self.middle.fd, sig) catch {};
    }
};

fn sleepMs(ms: i32) void {
    if (!is_linux) return;
    const every = std.os.linux.timespec{
        .sec = 0,
        .nsec = @as(isize, ms) * std.time.ns_per_ms,
    };
    _ = std.os.linux.nanosleep(&every, null);
}

fn portFrom(args: []const []const u8) error{Unreadable}!u32 {
    if (args.len == 0) return default_port;
    if (args.len != 2) return error.Unreadable;
    if (!std.mem.eql(u8, args[0], "--port")) return error.Unreadable;
    return std.fmt.parseInt(u32, args[1], 10) catch error.Unreadable;
}

pub fn serve(
    gpa: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    watch: ?*Watch,
) !void {
    while (true) {
        const line = wire.readLine(reader) catch |err| switch (err) {
            error.Ended, error.Broke => return,
            error.TooLong => {
                // The line is still there and must be discarded, or the loop reads it again.
                _ = reader.discardDelimiterInclusive('\n') catch return;
                try wire.write(writer, wire.Answer{
                    .refusal = "the request was longer than this build of chock-guest reads",
                });
                continue;
            },
            error.Unreadable => unreachable,
        };

        if (wire.cancelIn(line) != null) continue;

        const parsed = wire.parseLine(wire.Request, gpa, line) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TooLong, error.Unreadable, error.Ended, error.Broke => {
                try wire.write(writer, wire.Answer{
                    .refusal = "the request could not be read by this build of chock-guest",
                });
                continue;
            },
        };
        defer parsed.deinit();

        try answer(gpa, io, reader, writer, parsed.value, watch);
    }
}

fn answer(
    gpa: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    request: wire.Request,
    watch: ?*Watch,
) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var config = wire.configFor(arena, request) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Refused rather than run with a smaller trap set than the host asked for.
        error.UnknownTrap => return wire.write(writer, wire.Answer{
            .refusal = "the request named a syscall trap this build of chock-guest has no name for",
        }),
    };

    if (request.argv.len == 0) {
        return wire.write(writer, wire.Answer{
            .refusal = "the request named no program to run",
        });
    }

    // The sandbox root has to exist before the driver binds it onto itself.
    std.Io.Dir.cwd().createDirPath(io, config.root) catch |err| {
        const said = try std.fmt.allocPrint(
            arena,
            "the guest could not make the directory it builds a sandbox in: {t}",
            .{err},
        );
        return wire.write(writer, wire.Answer{ .refusal = said });
    };

    // A file and not a pipe: nothing drains a pipe while the driver blocks on the fork.
    var wrote_out = std.Io.Dir.cwd().createFile(io, wire.guest_output, .{
        .read = true,
        .truncate = true,
    }) catch |err| return wire.write(writer, wire.Answer{
        .refusal = try std.fmt.allocPrint(
            arena,
            "the guest could not make the file a call writes to: {t}",
            .{err},
        ),
    });
    defer wrote_out.close(io);

    var wrote_err = std.Io.Dir.cwd().createFile(io, wire.guest_output_err, .{
        .read = true,
        .truncate = true,
    }) catch |err| return wire.write(writer, wire.Answer{
        .refusal = try std.fmt.allocPrint(
            arena,
            "the guest could not make the file a call writes to: {t}",
            .{err},
        ),
    });
    defer wrote_err.close(io);

    config.stdout_fd = wrote_out.handle;
    config.stderr_fd = wrote_err.handle;

    // This process is root, so the helpers can take a second identity the call cannot read.
    config.hide_helpers = true;

    var reaching = HostNet{
        .io = io,
        .gpa = gpa,
        .reader = reader,
        .writer = writer,
        .watch = watch,
    };
    if (config.network != .none) config.net_router = reaching.router();

    setClock(io, request.now_ns);

    var report: Sandbox.LandlockReport = std.mem.zeroes(Sandbox.LandlockReport);

    var middle: ?*Sandbox.Middle = null;
    if (watch) |one| {
        one.middle = .{};
        one.armed.store(true, .release);
        middle = &one.middle;
    }
    defer if (watch) |one| Sandbox.closeMiddle(&one.middle);

    const term = Sandbox.spawn(arena, config, request.argv, &report, middle) catch |err| {
        // Disarmed before the answer goes out, never in a `defer`, or a watcher
        // still armed takes the host's next request for a cancel.
        if (watch) |one| one.armed.store(false, .release);
        const said = try std.fmt.allocPrint(arena, "the sandbox could not be built: {t}{s}", .{
            err,
            tailOf(arena, io, wrote_err) catch "",
        });
        return wire.write(writer, wire.Answer{ .refusal = said });
    };

    if (watch) |one| one.armed.store(false, .release);

    if (term == .signal) {
        const said = shortReadNote(arena, io, request);
        if (said.len != 0) {
            const at = if (wrote_err.stat(io)) |one| one.size else |_| 0;
            wrote_err.writePositionalAll(io, said, at) catch {};
        }
    }

    try sendOutput(io, writer, wrote_out, false);
    try sendOutput(io, writer, wrote_err, true);

    return wire.write(writer, wire.Answer{
        .ended = switch (term) {
            .exited => |code| .{ .exited = code },
            .signal => |sig| .{ .signalled = @intFromEnum(sig) },
            .stopped => |sig| .{ .stopped = @intFromEnum(sig) },
            .unknown => |code| .{ .unknown = code },
        },
        // A guest kernel with no Landlock at all is a fact the host must see.
        .landlock = .{ .applied = report.features.supported, .abi = report.abi },
    });
}

const HostNet = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    watch: ?*Watch,

    fn router(self: *HostNet) Sandbox.NetRouter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Sandbox.NetRouter.VTable = .{
        .resolve = resolveThunk,
        .open = openThunk,
    };

    fn resolveThunk(
        ptr: *anyopaque,
        host: []const u8,
        want: Sandbox.NetRouter.Family,
    ) Sandbox.NetRouter.Resolution {
        const self: *HostNet = @ptrCast(@alignCast(ptr));

        noteResolveAsked(host);

        if (self.watch) |one| one.reading.lockUncancelable(self.io);
        defer if (self.watch) |one| one.reading.unlock(self.io);

        wire.write(self.writer, wire.Resolve{
            .resolve = host,
            .ipv6 = want == .ipv6,
        }) catch |err| return noteResolve("asking the host", host, err);

        const line = wire.readLine(self.reader) catch |err|
            return noteResolve("reading the host's answer", host, err);
        const said = wire.parseLine(wire.Resolved, self.gpa, line) catch |err|
            return noteResolve("reading the host's answer", host, err);
        defer said.deinit();

        const text = said.value.address orelse {
            if (said.value.refused) {
                _ = noteResolve("the policy refused it", host, error.Refused);
                return .refused;
            }
            return noteResolve("the host gave no address", host, error.NoAddress);
        };
        const got = wire.addressIn(text) orelse
            return noteResolve("the address the host gave", host, error.BadAddress);
        noteResolveAsked("the host answered with an address for");
        return .{ .granted = got };
    }

    fn noteResolveAsked(host: []const u8) void {
        var room: [256]u8 = undefined;
        const line = std.fmt.bufPrint(
            &room,
            "chock guest: [{d}ms] resolving {s}\n",
            .{ nowMs(), host },
        ) catch "chock guest: resolving a name\n";
        _ = linux.write(std.posix.STDERR_FILENO, line.ptr, line.len);
    }

    fn nowMs() i64 {
        var at: linux.timespec = undefined;
        if (linux.clock_gettime(.MONOTONIC, &at) != 0) return 0;
        return @as(i64, at.sec) * 1000 + @divTrunc(at.nsec, 1_000_000);
    }

    fn noteResolve(
        what: []const u8,
        host: []const u8,
        err: anyerror,
    ) Sandbox.NetRouter.Resolution {
        var room: [256]u8 = undefined;
        const line = std.fmt.bufPrint(
            &room,
            "chock guest: resolving {s} failed at {s}: {s}\n",
            .{ host, what, @errorName(err) },
        ) catch "chock guest: resolving a name failed\n";
        _ = linux.write(std.posix.STDERR_FILENO, line.ptr, line.len);
        return .unresolved;
    }

    fn openThunk(
        ptr: *anyopaque,
        address: Sandbox.NetRouter.Address,
        port: u16,
    ) Sandbox.NetBroker.Grant {
        const self: *HostNet = @ptrCast(@alignCast(ptr));
        _ = self;

        const fd = dialHost(reaching_port) catch return .refused;
        errdefer _ = linux.close(fd);

        var room: [wire.max_reaching_text]u8 = undefined;
        var line: [wire.max_reaching_text + 16]u8 = undefined;
        const said = std.fmt.bufPrint(&line, "{s} {d}\n", .{
            wire.writeAddress(&room, address),
            port,
        }) catch return .refused;

        var sent: usize = 0;
        while (sent < said.len) {
            const wrote = linux.write(fd, said[sent..].ptr, said.len - sent);
            if (linux.errno(wrote) != .SUCCESS) {
                _ = linux.close(fd);
                return .refused;
            }
            sent += wrote;
        }
        return .{ .granted = fd };
    }
};

const reaching_port: u32 = 1025;

const clock_slack_ns: i128 = std.time.ns_per_s;

fn setClock(io: std.Io, now_ns: i64) void {
    if (!is_linux or now_ns == 0) return;

    const held: i128 = std.Io.Timestamp.now(io, .real).nanoseconds;
    const apart = if (held > now_ns) held - now_ns else @as(i128, now_ns) - held;
    if (apart < clock_slack_ns) return;

    const wanted = std.os.linux.timespec{
        .sec = @intCast(@divTrunc(now_ns, std.time.ns_per_s)),
        .nsec = @intCast(@mod(now_ns, std.time.ns_per_s)),
    };
    _ = std.os.linux.clock_settime(.REALTIME, &wanted);
}

const probe_read_bytes: usize = 128 * 1024;

fn shortReadNote(
    arena: std.mem.Allocator,
    io: std.Io,
    request: wire.Request,
) []const u8 {
    if (request.argv.len == 0) return "";
    const here = whereGuestSees(arena, request, request.argv[0]) orelse return "";

    const file = std.Io.Dir.cwd().openFile(io, here, .{}) catch return "";
    defer file.close(io);
    const size = (file.stat(io) catch return "").size;

    const room = arena.alloc(u8, probe_read_bytes) catch return "";
    const wanted = @min(size, room.len);
    if (wanted == 0) return "";

    const got = std.os.linux.pread(file.handle, room.ptr, wanted, 0);
    if (std.os.linux.errno(got) != .SUCCESS or got >= wanted) return "";

    return std.fmt.allocPrint(
        arena,
        "\nchock guest: one read of {d} bytes of {s} answered {d}. The filesystem the host " ++
            "offered this guest answers short, and a page fault cannot ask again, so the " ++
            "program died on a page that was never filled.\n",
        .{ wanted, here, got },
    ) catch "";
}

fn whereGuestSees(
    arena: std.mem.Allocator,
    request: wire.Request,
    wanted: []const u8,
) ?[]const u8 {
    var best: ?[]const u8 = null;
    var longest: usize = 0;
    for (request.mounts) |one| switch (one) {
        .bind => |b| {
            if (b.target.len <= longest) continue;
            if (!std.mem.startsWith(u8, wanted, b.target)) continue;
            longest = b.target.len;
            best = std.fmt.allocPrint(arena, "{s}{s}", .{ b.source, wanted[b.target.len..] }) catch null;
        },
        else => {},
    };
    return best;
}

fn tailOf(
    arena: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
) std.mem.Allocator.Error![]const u8 {
    const size = if (file.stat(io)) |one| one.size else |_| return "";
    if (size == 0) return "";

    var buffer: [max_fault_tail]u8 = undefined;
    const want: usize = @intCast(@min(size, buffer.len));
    const from = size - want;
    const got = file.readPositionalAll(io, buffer[0..want], from) catch return "";

    const said = std.mem.trim(u8, buffer[0..got], " \t\r\n");
    if (said.len == 0) return "";
    return std.fmt.allocPrint(arena, ", and it said: {s}", .{said});
}

const max_fault_tail: usize = 512;

fn sendOutput(io: std.Io, writer: *std.Io.Writer, file: std.Io.File, is_err: bool) !void {
    const size = if (file.stat(io)) |one| one.size else |_| 0;
    const sending = @min(size, wire.max_output_bytes);
    try wire.write(writer, wire.Output{ .output = sending, .err = is_err });
    if (sending == 0) return;

    var chunk: [64 * 1024]u8 = undefined;
    var sent: u64 = 0;
    while (sent < sending) {
        const want: usize = @intCast(@min(sending - sent, chunk.len));
        const got = file.readPositionalAll(io, chunk[0..want], sent) catch 0;
        if (got == 0) break;
        try writer.writeAll(chunk[0..got]);
        sent += got;
    }
    while (sent < sending) : (sent += 1) try writer.writeByte(0);
    try writer.flush();
}

const testing = std.testing;

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

    try serve(testing.allocator, testing.io, &reader, &writer, null);

    const said = writer.buffered();
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, said, "\n"));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, said, "named no program"));
    try testing.expect(std.mem.indexOf(u8, said, "\"ended\":null") != null);
}

test "a cancel between calls is dropped, and the request after it is still answered" {
    var in_buffer: [4096]u8 = undefined;
    const tail = try script(in_buffer[512..], &.{nothing_to_run});

    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(testing.allocator);
    try joined.appendSlice(testing.allocator, wire.cancel_kill);
    try joined.appendSlice(testing.allocator, tail);

    var reader = std.Io.Reader.fixed(joined.items);
    var out_buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    try serve(testing.allocator, testing.io, &reader, &writer, null);

    const said = writer.buffered();
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, said, "\n"));
    try testing.expect(std.mem.indexOf(u8, said, "named no program") != null);
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

    try serve(testing.allocator, testing.io, &reader, &writer, null);

    const said = writer.buffered();
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, said, "\n"));
    try testing.expect(std.mem.indexOf(u8, said, "could not be read") != null);
    try testing.expect(std.mem.indexOf(u8, said, "named no program") != null);
}

test "a stream that ends with nothing on it is not an error" {
    var reader = std.Io.Reader.fixed("");
    var out_buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    try serve(testing.allocator, testing.io, &reader, &writer, null);
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "this program resolves nothing and holds no policy" {
    const own_source = @embedFile("guest.zig");
    for ([_][]const u8{
        "getAddressList",
        "addressIsReachable",
        "resolve",
        "chock-policy",
        "chock-broker",
    }) |name| {
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

    try testing.expectError(error.Unreadable, portFrom(&.{"2048"}));
    try testing.expectError(error.Unreadable, portFrom(&.{ "--port", "not-a-number" }));
    try testing.expectError(error.Unreadable, portFrom(&.{ "-p", "2048" }));
    try testing.expectError(error.Unreadable, portFrom(&.{ "--port", "1", "2" }));
}

fn pair() ![2]std.posix.fd_t {
    if (!is_linux) return error.SkipZigTest;

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

    const host = std.Io.File{ .handle = host_end, .flags = .{ .nonblocking = false } };

    var read_buffer: [8192]u8 = undefined;
    var write_buffer: [8192]u8 = undefined;
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

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var request_buffer: [8192]u8 = undefined;
    var writing = host.writer(io, &request_buffer);
    var share_fault: ?chock_sandbox.vm_shares.Fault = null;
    const moved = try chock_sandbox.vm_shares.translate(arena, config, guest.shares, &share_fault);
    const asked = (try wire.requestFor(arena, moved, &.{})).?;
    try wire.write(&writing.interface, asked);

    try testing.expectEqualStrings("/mnt/shares/store/aaa-jq", asked.mounts[0].bind.source);
    try testing.expectEqualStrings("/nix/store/aaa-jq", asked.mounts[0].bind.target);

    const guest_stream = std.Io.File{ .handle = guest_end, .flags = .{ .nonblocking = false } };
    var guest_read: [8192]u8 = undefined;
    var guest_write: [8192]u8 = undefined;
    var guest_reader = guest_stream.reader(io, &guest_read);
    var guest_writer = guest_stream.writer(io, &guest_write);

    _ = linux.shutdown(host_end, linux.SHUT.WR);
    try serve(gpa, io, &guest_reader.interface, &guest_writer.interface, null);
    _ = linux.close(guest_end);

    var answer_buffer: [8192]u8 = undefined;
    var answer_reader = host.reader(io, &answer_buffer);
    const said = try wire.read(wire.Answer, gpa, &answer_reader.interface);
    defer said.deinit();
    try testing.expectEqual(@as(?wire.Answer.Ended, null), said.value.ended);
    try testing.expect(std.mem.indexOf(u8, said.value.refusal.?, "named no program") != null);
}
