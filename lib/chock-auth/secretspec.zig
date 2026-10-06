//! A fourth `store.Secrets` driver: SecretSpec, a secrets tool from Cachix

const std = @import("std");
const store = @import("store.zig");

pub const Fault = enum {
    not_installed, // the program is not on PATH
    start_failed, // it would not run
    protocol_error, // it answered something this cannot read
    refused, // it answered a JSON-RPC error
    read_only, // set is not available
    timed_out,
};

pub fn adviceFor(fault: Fault) ?[]const u8 {
    return switch (fault) {
        .not_installed => "SecretSpec is not installed: put \"secretspec\" on PATH, or choose " ++
            "another credentials store.",
        .start_failed => "secretspec serve would not start. Check that secretspec.toml is valid " ++
            "and that its configured backend is reachable.",
        .protocol_error => "secretspec answered something this driver could not read. Check that " ++
            "its version matches what this build of Chock expects.",
        .refused => "secretspec refused the request. Run secretspec check to see what it reports.",
        .read_only => "secretspec is running read only, or this credential's name is not declared " ++
            "in secretspec.toml. Add it there, or choose another credentials store.",
        .timed_out => "secretspec did not answer in time. Its backend may be waiting on a " ++
            "network call, or on a person who is not there to answer it.",
    };
}

pub const max_refusal_bytes: usize = 240;

pub const request_deadline_ms: i64 = 10_000;

const max_frame_bytes: usize = 1 << 20;

const program_name = "secretspec";
const method_get = "resolver.get";
const method_set = "resolver.set";
const method_release = "resolver.release";
const representation_value = "value";
const representation_path = "path";
const purpose_consumer = "chock";
const purpose_operation = "credential";

pub const Driver = struct {
    env: ?*const std.process.Environ.Map = null,
    last_fault: ?Fault = null,

    pub fn secrets(self: *const Driver) store.Secrets {
        return .{ .ptr = @constCast(self), .vtable = &vtable };
    }

    const vtable = store.Secrets.VTable{ .get = getFn, .put = putFn };

    fn getFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        diag: ?*?store.Diagnostic,
    ) store.Error!?[]u8 {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        self.last_fault = null;

        const env = self.env orelse return self.fault(.not_installed, true);
        const program = (try resolveOnPath(gpa, io, env, program_name)) orelse
            return self.fault(.not_installed, true);
        defer gpa.free(program);

        var child = spawnServer(io, program, env, true) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return self.fault(.start_failed, true);
        };
        // This kills and reaps the child on every path out of this function, closing its pipes too.
        defer child.kill(io);

        const deadline = callDeadline(io);

        const request = buildGetRequest(gpa, 1, name, wallDeadlineMs(io)) catch return error.OutOfMemory;
        defer {
            std.crypto.secureZero(u8, request);
            gpa.free(request);
        }
        writeFramed(child.stdin.?, io, request, deadline) catch |err| return mapTransportError(self, err, true);

        const line = readFrame(gpa, io, child.stdout.?, deadline) catch |err| return mapTransportError(self, err, true);
        defer {
            std.crypto.secureZero(u8, line);
            gpa.free(line);
        }

        const parsed = parseGetReply(gpa, line) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return self.fault(.protocol_error, true);
        };
        switch (parsed) {
            .absent => return null,
            .refused => |said| {
                defer if (said) |text| gpa.free(text);
                return self.faultSaying(gpa, diag, said, .refused, true);
            },
            .path_returned => |lease_id| {
                defer gpa.free(lease_id);
                const release = buildReleaseRequest(gpa, 2, lease_id) catch null;
                if (release) |bytes| {
                    defer gpa.free(bytes);
                    writeFramed(child.stdin.?, io, bytes, deadline) catch {};
                }
                return self.fault(.protocol_error, true);
            },
            .value => |value| return value,
        }
    }

    fn putFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        value: []const u8,
        diag: ?*?store.Diagnostic,
    ) store.Error!void {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        self.last_fault = null;

        const env = self.env orelse return self.fault(.not_installed, false);
        const program = (try resolveOnPath(gpa, io, env, program_name)) orelse
            return self.fault(.not_installed, false);
        defer gpa.free(program);

        var child = spawnServer(io, program, env, false) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return self.fault(.start_failed, false);
        };
        defer child.kill(io);

        const deadline = callDeadline(io);

        const request = buildSetRequest(gpa, 1, name, value, wallDeadlineMs(io)) catch return error.OutOfMemory;
        defer {
            std.crypto.secureZero(u8, request);
            gpa.free(request);
        }
        writeFramed(child.stdin.?, io, request, deadline) catch |err| return mapTransportError(self, err, false);

        const line = readFrame(gpa, io, child.stdout.?, deadline) catch |err| return mapTransportError(self, err, false);
        defer {
            std.crypto.secureZero(u8, line);
            gpa.free(line);
        }

        const outcome = parseSetReply(gpa, line) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return self.fault(.protocol_error, false);
        };
        switch (outcome) {
            .stored => return,
            .refused => |said| {
                defer if (said) |text| gpa.free(text);
                return self.faultSaying(gpa, diag, said, .read_only, false);
            },
        }
    }

    fn fault(self: *Driver, kind: Fault, unreadable: bool) store.Error {
        return self.faultSaying(null, null, null, kind, unreadable);
    }

    fn faultSaying(
        self: *Driver,
        gpa: ?std.mem.Allocator,
        diag: ?*?store.Diagnostic,
        detail: ?[]const u8,
        kind: Fault,
        unreadable: bool,
    ) store.Error {
        self.last_fault = kind;
        if (gpa) |allocator| {
            if (store.wantsDiagnostic(diag)) {
                const copied: ?[]u8 = if (detail) |text| allocator.dupe(u8, text) catch null else null;
                _ = store.note(diag, .{ .secretspec_refused = .{
                    .verb = if (unreadable) store.reading_verb else store.storing_verb,
                    .fault = kind,
                    .detail = copied,
                } });
            }
        }
        return if (unreadable) error.StoreUnreadable else error.StoreUnwritable;
    }
};

const TransportError = error{ TimedOut, Closed, WriteFailed, FrameTooLarge } || std.mem.Allocator.Error;

fn mapTransportError(self: *Driver, err: TransportError, unreadable: bool) store.Error {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    const kind: Fault = switch (err) {
        error.TimedOut => .timed_out,
        error.Closed, error.WriteFailed, error.FrameTooLarge => .protocol_error,
        error.OutOfMemory => unreachable,
    };
    return self.fault(kind, unreadable);
}

fn callDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
        .raw = .fromNanoseconds(request_deadline_ms * std.time.ns_per_ms),
        .clock = .awake,
    });
}

fn wallDeadlineMs(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .real).toMilliseconds() + request_deadline_ms;
}

fn remainingMs(io: std.Io, deadline: std.Io.Clock.Timestamp) ?i32 {
    const left = deadline.durationFromNow(io).raw.toMilliseconds();
    if (left <= 0) return null;
    return if (left > std.math.maxInt(i32)) std.math.maxInt(i32) else @intCast(left);
}

fn pollReady(fd: std.posix.fd_t, events: i16, timeout_ms: i32) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    const ready = std.posix.poll(&fds, timeout_ms) catch return true;
    return ready != 0;
}

fn writeFramed(file: std.Io.File, io: std.Io, bytes: []const u8, deadline: std.Io.Clock.Timestamp) TransportError!void {
    var index: usize = 0;
    while (index < bytes.len) {
        const timeout_ms = remainingMs(io, deadline) orelse return error.TimedOut;
        if (!pollReady(file.handle, std.posix.POLL.OUT, timeout_ms)) return error.TimedOut;
        const written = std.Io.File.writeStreaming(file, io, &.{}, &.{bytes[index..]}, 1) catch return error.WriteFailed;
        index += written;
    }
}

fn readFrame(gpa: std.mem.Allocator, io: std.Io, file: std.Io.File, deadline: std.Io.Clock.Timestamp) TransportError![]u8 {
    var frame: Frame = .{};
    defer frame.deinit(gpa);

    var chunk: [4096]u8 = undefined;
    while (true) {
        if (try frame.takeLine(gpa)) |line| return line;

        const timeout_ms = remainingMs(io, deadline) orelse return error.TimedOut;
        if (!pollReady(file.handle, std.posix.POLL.IN, timeout_ms)) return error.TimedOut;

        var bufs: [1][]u8 = .{&chunk};
        const count = std.Io.File.readStreaming(file, io, &bufs) catch return error.Closed;
        try frame.append(gpa, chunk[0..count]);
    }
}

const Frame = struct {
    buffer: std.ArrayList(u8) = .empty,

    fn append(self: *Frame, gpa: std.mem.Allocator, bytes: []const u8) error{ FrameTooLarge, OutOfMemory }!void {
        if (self.buffer.items.len + bytes.len > max_frame_bytes) return error.FrameTooLarge;
        try self.buffer.appendSlice(gpa, bytes);
    }

    fn takeLine(self: *Frame, gpa: std.mem.Allocator) std.mem.Allocator.Error!?[]u8 {
        const end = std.mem.indexOfScalar(u8, self.buffer.items, '\n') orelse return null;
        const line = try gpa.dupe(u8, self.buffer.items[0..end]);
        self.buffer.replaceRange(gpa, 0, end + 1, &.{}) catch unreachable;
        return line;
    }

    fn deinit(self: *Frame, gpa: std.mem.Allocator) void {
        self.buffer.deinit(gpa);
    }
};

fn resolveOnPath(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    name: []const u8,
) std.mem.Allocator.Error!?[]u8 {
    const path_value = env.get("PATH") orelse return null;
    var it = std.mem.tokenizeScalar(u8, path_value, ':');
    while (it.next()) |dir| {
        const candidate = try std.fs.path.join(gpa, &.{ dir, name });
        const stat = std.Io.Dir.cwd().statFile(io, candidate, .{}) catch {
            gpa.free(candidate);
            continue;
        };
        if (stat.kind == .directory) {
            gpa.free(candidate);
            continue;
        }
        return candidate;
    }
    return null;
}

fn spawnServer(
    io: std.Io,
    program: []const u8,
    env: *const std.process.Environ.Map,
    read_only: bool,
) std.process.SpawnError!std.process.Child {
    const argv: []const []const u8 = if (read_only)
        &.{ program, "serve", "--read-only" }
    else
        &.{ program, "serve" };
    return std.process.spawn(io, .{
        .argv = argv,
        .environ_map = env,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
}

fn buildGetRequest(
    gpa: std.mem.Allocator,
    id: i64,
    name: []const u8,
    deadline_unix_ms: i64,
) std.mem.Allocator.Error![]u8 {
    return std.json.Stringify.valueAlloc(gpa, .{
        .jsonrpc = "2.0",
        .id = id,
        .method = method_get,
        ._meta = .{ .deadline_unix_ms = deadline_unix_ms },
        .params = .{
            .name = name,
            .representation = representation_value,
            .purpose = .{ .consumer = purpose_consumer, .operation = purpose_operation },
        },
    }, .{});
}

fn buildSetRequest(
    gpa: std.mem.Allocator,
    id: i64,
    name: []const u8,
    value: []const u8,
    deadline_unix_ms: i64,
) std.mem.Allocator.Error![]u8 {
    return std.json.Stringify.valueAlloc(gpa, .{
        .jsonrpc = "2.0",
        .id = id,
        .method = method_set,
        ._meta = .{ .deadline_unix_ms = deadline_unix_ms },
        .params = .{
            .name = name,
            .value = value,
            .representation = representation_value,
            .purpose = .{ .consumer = purpose_consumer, .operation = purpose_operation },
        },
    }, .{});
}

fn buildReleaseRequest(gpa: std.mem.Allocator, id: i64, path_lease_id: []const u8) std.mem.Allocator.Error![]u8 {
    return std.json.Stringify.valueAlloc(gpa, .{
        .jsonrpc = "2.0",
        .id = id,
        .method = method_release,
        .params = .{ .path_lease_id = path_lease_id },
    }, .{});
}

const ParseError = error{NotJson} || std.mem.Allocator.Error;

const GetOutcome = union(enum) {
    value: []u8,
    absent,
    refused: ?[]u8,
    path_returned: []u8,
};

fn refusalText(gpa: std.mem.Allocator, failed: std.json.Value) std.mem.Allocator.Error!?[]u8 {
    if (failed != .object) return null;
    const message = failed.object.get("message") orelse return null;
    if (message != .string) return null;
    if (message.string.len == 0) return null;

    const kept = message.string[0..@min(message.string.len, max_refusal_bytes)];
    return try gpa.dupe(u8, kept);
}

fn parseGetReply(gpa: std.mem.Allocator, bytes: []const u8) ParseError!GetOutcome {
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, bytes, .{}) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return error.NotJson;
    };
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return error.NotJson;

    // What the server said is the useful part: a secret a project has not declared, or a provider that would not answer, is named here. The child's own error stream is not read, because draining an unbounded pipe from another program is its own hazard.
    if (root.object.get("error")) |failed| {
        return .{ .refused = refusalText(gpa, failed) catch null };
    }

    const result = root.object.get("result") orelse return error.NotJson;
    if (result != .object) return error.NotJson;

    const status = result.object.get("status") orelse return error.NotJson;
    if (status != .string) return error.NotJson;
    if (std.mem.eql(u8, status.string, "undeclared") or std.mem.eql(u8, status.string, "missing")) {
        return .absent;
    }
    if (!std.mem.eql(u8, status.string, "resolved")) return error.NotJson;

    const representation = result.object.get("representation") orelse return error.NotJson;
    if (representation != .string) return error.NotJson;

    if (std.mem.eql(u8, representation.string, representation_path)) {
        const lease = result.object.get("path_lease_id") orelse return error.NotJson;
        if (lease != .string) return error.NotJson;
        return .{ .path_returned = try gpa.dupe(u8, lease.string) };
    }
    if (!std.mem.eql(u8, representation.string, representation_value)) return error.NotJson;

    const value = result.object.get("value") orelse return error.NotJson;
    if (value != .string) return error.NotJson;
    return .{ .value = try gpa.dupe(u8, value.string) };
}

const SetOutcome = union(enum) {
    stored,
    refused: ?[]u8,
};

fn parseSetReply(gpa: std.mem.Allocator, bytes: []const u8) ParseError!SetOutcome {
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, bytes, .{}) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return error.NotJson;
    };
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return error.NotJson;

    if (root.object.get("error")) |failed| {
        return .{ .refused = refusalText(gpa, failed) catch null };
    }
    if (root.object.get("result")) |_| return .stored;
    return error.NotJson;
}

const testing = std.testing;

const WireGetRequest = struct {
    jsonrpc: []const u8,
    id: i64,
    method: []const u8,
    params: struct {
        name: []const u8,
        representation: []const u8,
        purpose: struct {
            consumer: []const u8,
            operation: []const u8,
        },
    },
};

test "the request this builds for get is valid JSON and round trips whole" {
    const gpa = testing.allocator;
    const body = try buildGetRequest(gpa, 2, "work", 1_786_766_405_000);
    defer gpa.free(body);

    const parsed = try std.json.parseFromSlice(WireGetRequest, gpa, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    try testing.expectEqualStrings("2.0", parsed.value.jsonrpc);
    try testing.expectEqual(@as(i64, 2), parsed.value.id);
    try testing.expectEqualStrings(method_get, parsed.value.method);
    try testing.expectEqualStrings("work", parsed.value.params.name);
    try testing.expectEqualStrings("value", parsed.value.params.representation);
    try testing.expectEqualStrings("chock", parsed.value.params.purpose.consumer);
    try testing.expectEqualStrings("credential", parsed.value.params.purpose.operation);
}

test "a resolved reply gives the value byte for byte, quote, backslash and newline intact" {
    const gpa = testing.allocator;
    const value = "sk-\"quoted\"\\newline\nend";
    const body = try std.json.Stringify.valueAlloc(gpa, .{
        .jsonrpc = "2.0",
        .id = 2,
        .result = .{
            .status = "resolved",
            .representation = "value",
            .value = value,
            .source = "provider",
            .source_provider = "keyring://",
        },
    }, .{});
    defer gpa.free(body);

    const outcome = try parseGetReply(gpa, body);
    const got = outcome.value;
    defer gpa.free(got);
    try testing.expectEqualStrings(value, got);
}

test "undeclared and missing both give null, and neither is an error" {
    const gpa = testing.allocator;
    for ([_][]const u8{ "undeclared", "missing" }) |status| {
        const body = try std.json.Stringify.valueAlloc(gpa, .{
            .jsonrpc = "2.0",
            .id = 2,
            .result = .{ .status = status },
        }, .{});
        defer gpa.free(body);

        try testing.expectEqual(GetOutcome.absent, try parseGetReply(gpa, body));
    }
}

test "a JSON-RPC error reply gives the refused outcome" {
    const gpa = testing.allocator;
    const body = try std.json.Stringify.valueAlloc(gpa, .{
        .jsonrpc = "2.0",
        .id = 2,
        .@"error" = .{ .code = -32000, .message = "no such secret" },
    }, .{});
    defer gpa.free(body);

    const refused = try parseGetReply(gpa, body);
    defer switch (refused) {
        .refused => |text| if (text) |held| gpa.free(held),
        else => {},
    };
    try testing.expect(refused == .refused);
}

test "a reply that is not JSON at all is refused rather than read" {
    const gpa = testing.allocator;
    try testing.expectError(error.NotJson, parseGetReply(gpa, "not json, and no braces either"));
}

test "a path representation is refused rather than read as a value" {
    const gpa = testing.allocator;
    const body = try std.json.Stringify.valueAlloc(gpa, .{
        .jsonrpc = "2.0",
        .id = 2,
        .result = .{
            .status = "resolved",
            .representation = "path",
            .path_lease_id = "lease-1",
        },
    }, .{});
    defer gpa.free(body);

    const outcome = try parseGetReply(gpa, body);
    switch (outcome) {
        .path_returned => |lease_id| {
            defer gpa.free(lease_id);
            try testing.expectEqualStrings("lease-1", lease_id);
        },
        else => try testing.expect(false),
    }
}

test "a frame over the one mebibyte cap is refused rather than read" {
    const gpa = testing.allocator;
    var frame: Frame = .{};
    defer frame.deinit(gpa);

    const chunk: [4096]u8 = @splat('x');
    var held: usize = 0;
    while (held + chunk.len <= max_frame_bytes) : (held += chunk.len) {
        try frame.append(gpa, &chunk);
    }
    try testing.expectError(error.FrameTooLarge, frame.append(gpa, &chunk));
}

test "adviceFor gives a distinct sentence for every fault, and not_installed names the program" {
    const all = [_]Fault{ .not_installed, .start_failed, .protocol_error, .refused, .read_only, .timed_out };
    for (all, 0..) |one, i| {
        const advice = adviceFor(one) orelse continue;
        for (all[i + 1 ..]) |other| {
            const other_advice = adviceFor(other) orelse continue;
            try testing.expect(!std.mem.eql(u8, advice, other_advice));
        }
    }
    try testing.expect(std.mem.indexOf(u8, adviceFor(.not_installed).?, "secretspec") != null);
}

test "the request this builds for put carries the value, and round trips whole" {
    const gpa = testing.allocator;
    const body = try buildSetRequest(gpa, 3, "work", "sk-not-a-real-key", 1_786_766_405_000);
    defer gpa.free(body);

    const Wire = struct {
        method: []const u8,
        params: struct { name: []const u8, value: []const u8 },
    };
    const parsed = try std.json.parseFromSlice(Wire, gpa, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    try testing.expectEqualStrings(method_set, parsed.value.method);
    try testing.expectEqualStrings("work", parsed.value.params.name);
    try testing.expectEqualStrings("sk-not-a-real-key", parsed.value.params.value);
}

test "a set reply is told apart as stored or refused" {
    const gpa = testing.allocator;
    const stored = try std.json.Stringify.valueAlloc(gpa, .{
        .jsonrpc = "2.0",
        .id = 3,
        .result = .{ .status = "stored" },
    }, .{});
    defer gpa.free(stored);
    try testing.expectEqual(SetOutcome.stored, try parseSetReply(gpa, stored));

    const refused = try std.json.Stringify.valueAlloc(gpa, .{
        .jsonrpc = "2.0",
        .id = 3,
        .@"error" = .{ .code = -32001, .message = "read only" },
    }, .{});
    defer gpa.free(refused);
    const said = try parseSetReply(gpa, refused);
    defer switch (said) {
        .refused => |text| if (text) |held| gpa.free(held),
        else => {},
    };
    try testing.expect(said == .refused);
}

test "a Driver with no environment refuses rather than reaching for a program" {
    const gpa = testing.allocator;
    var driver = Driver{};

    try testing.expectError(error.StoreUnreadable, driver.secrets().get(gpa, testing.io, "work", null));
    try testing.expectEqual(Fault.not_installed, driver.last_fault.?);

    try testing.expectError(error.StoreUnwritable, driver.secrets().put(gpa, testing.io, "work", "x", null));
    try testing.expectEqual(Fault.not_installed, driver.last_fault.?);
}

test "what the server said about a refusal reaches the caller" {
    const gpa = testing.allocator;
    const body =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32004,"message":"secret FORGE_TOKEN is not declared in secretspec.toml"}}
    ;
    const outcome = try parseGetReply(gpa, body);
    defer switch (outcome) {
        .refused => |text| if (text) |held| gpa.free(held),
        else => {},
    };

    const said = switch (outcome) {
        .refused => |text| text,
        else => return error.TestExpectedRefusal,
    };
    try testing.expect(std.mem.indexOf(u8, said.?, "FORGE_TOKEN") != null);
}

test "a refusal longer than the bound is cut rather than carried whole" {
    const gpa = testing.allocator;
    const long = "x" ** (max_refusal_bytes + 200);
    const body = try std.fmt.allocPrint(
        gpa,
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{{\"code\":-32000,\"message\":\"{s}\"}}}}",
        .{long},
    );
    defer gpa.free(body);

    const outcome = try parseGetReply(gpa, body);
    defer switch (outcome) {
        .refused => |text| if (text) |held| gpa.free(held),
        else => {},
    };
    const said = switch (outcome) {
        .refused => |text| text,
        else => return error.TestExpectedRefusal,
    };
    try testing.expectEqual(max_refusal_bytes, said.?.len);
}

test "a refusal that says nothing readable carries nothing rather than guessing" {
    const gpa = testing.allocator;
    for ([_][]const u8{
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000}}",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"\"}}",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":7}}",
    }) |body| {
        const outcome = try parseGetReply(gpa, body);
        defer switch (outcome) {
            .refused => |text| if (text) |held| gpa.free(held),
            else => {},
        };
        const said = switch (outcome) {
            .refused => |text| text,
            else => return error.TestExpectedRefusal,
        };
        try testing.expectEqual(@as(?[]u8, null), said);
    }
}
