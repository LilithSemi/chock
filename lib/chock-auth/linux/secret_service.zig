//! A second Linux credential driver, over the freedesktop secret service.

const std = @import("std");
const dbus = @import("dbus");
const store = @import("../store.zig");

const linux = std.os.linux;

pub const call_deadline_ms: i64 = 5000;

pub const unlock_deadline_ms: i64 = 120_000;

const prompt_iface = "org.freedesktop.Secret.Prompt";

pub const service_name = "chock";

const bus_name = "org.freedesktop.secrets";
const root_path = "/org/freedesktop/secrets";
const default_collection_path = "/org/freedesktop/secrets/aliases/default";
const service_iface = "org.freedesktop.Secret.Service";
const collection_iface = "org.freedesktop.Secret.Collection";
const item_iface = "org.freedesktop.Secret.Item";
const plain_algorithm = "plain";
const label_property = "org.freedesktop.Secret.Item.Label";
const attributes_property = "org.freedesktop.Secret.Item.Attributes";
const content_type = "text/plain; charset=utf8";

const faults = @import("secret_fault.zig");

pub const Fault = faults.Fault;
pub const adviceFor = faults.adviceFor;

const InternalError = error{
    NoSessionBus,
    ServiceUnavailable,
    CallFailed,
    CollectionLocked,
    BadReply,
    ValueTooLong,
} || std.mem.Allocator.Error;

const locked_error_names = [_][]const u8{
    "org.freedesktop.Secret.Error.IsLocked",
    "org.freedesktop.DBus.Error.AccessDenied",
};

fn isLockedErrorName(named: []const u8) bool {
    for (locked_error_names) |one| {
        if (std.mem.eql(u8, one, named)) return true;
    }
    return false;
}

fn badReplyOr(err: anytype) InternalError {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    return error.BadReply;
}

const Resolved = struct {
    path: []u8,
    abstract: bool,

    fn deinit(self: *Resolved, gpa: std.mem.Allocator) void {
        gpa.free(self.path);
    }
};

fn resolveSessionAddress(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    uid: linux.uid_t,
) std.mem.Allocator.Error!Resolved {
    if (env.get("DBUS_SESSION_BUS_ADDRESS")) |value| {
        if (try parseFirstUnix(gpa, value)) |resolved| return resolved;
    }
    return .{ .path = try std.fmt.allocPrint(gpa, "/run/user/{d}/bus", .{uid}), .abstract = false };
}

fn parseFirstUnix(gpa: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error!?Resolved {
    const list = dbus.address.parse(gpa, value) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return null;
    };
    defer list.deinit(gpa);
    for (list.items) |addr| {
        if (addr.kind != .unix) continue;
        if (addr.path) |p| return .{ .path = try gpa.dupe(u8, p), .abstract = false };
        if (addr.abstract) |a| return .{ .path = try gpa.dupe(u8, a), .abstract = true };
    }
    return null;
}

const Reply = struct {
    body: []u8,
    signature: []u8,
    endian: std.builtin.Endian,

    fn deinit(self: *Reply, gpa: std.mem.Allocator) void {
        gpa.free(self.body);
        gpa.free(self.signature);
    }
};

const Waiter = struct {
    gpa: std.mem.Allocator,
    done: bool = false,
    disconnected: bool = false,
    is_return: bool = false,
    oom: bool = false,
    body: []u8 = &.{},
    signature: []u8 = &.{},
    endian: std.builtin.Endian = .little,
    error_name: []u8 = &.{},

    fn onReply(ctx: ?*anyopaque, conn: *dbus.connection.Connection, reply: ?*const dbus.Message) void {
        _ = conn;
        const self: *Waiter = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse {
            self.disconnected = true;
            return;
        };
        self.is_return = r.msg_type == .method_return;
        if (!self.is_return) {
            // Copied here because the message is invalid the moment this returns. An allocation failure loses only the reason, so the call still fails rather than failing twice.
            if (r.error_name) |named| self.error_name = self.gpa.dupe(u8, named) catch &.{};
            return;
        }
        self.endian = r.endian;
        const body_copy = self.gpa.dupe(u8, r.body) catch {
            self.oom = true;
            return;
        };
        const sig_copy = self.gpa.dupe(u8, r.body_signature orelse "") catch {
            self.gpa.free(body_copy);
            self.oom = true;
            return;
        };
        self.body = body_copy;
        self.signature = sig_copy;
    }
};

fn callAndWait(
    io: std.Io,
    bus: *dbus.client.Bus,
    loop: *dbus.event_loop.EventLoop,
    gpa: std.mem.Allocator,
    msg: dbus.Message,
    deadline_ms: i64,
) InternalError!Reply {
    var waiter = Waiter{ .gpa = gpa };
    _ = bus.call(msg, Waiter.onReply, &waiter) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return error.CallFailed;
    };

    const slice_ms: i32 = 50;
    const deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
        .raw = .fromNanoseconds(deadline_ms * std.time.ns_per_ms),
        .clock = .awake,
    });
    while (!waiter.done) {
        _ = loop.dispatch(slice_ms);
        if (!std.Io.Clock.Timestamp.now(io, .awake).compare(.lt, deadline)) return error.CallFailed;
    }
    if (waiter.oom) return error.OutOfMemory;
    defer gpa.free(waiter.error_name);
    if (waiter.disconnected) return error.CallFailed;
    if (!waiter.is_return) {
        // The error name is read because it is what says why: without it, a locked collection and a genuine fault would be the same message, and the advice about unlocking would reach nobody.
        if (isLockedErrorName(waiter.error_name)) return error.CollectionLocked;
        return error.CallFailed;
    }
    return .{ .body = waiter.body, .signature = waiter.signature, .endian = waiter.endian };
}

const Opened = struct {
    loop: *dbus.event_loop.EventLoop,
    bus: *dbus.client.Bus,
    session_path: []u8,

    fn deinit(self: *Opened, gpa: std.mem.Allocator) void {
        gpa.free(self.session_path);
        self.bus.deinit();
        self.loop.deinit();
        gpa.destroy(self.loop);
    }
};

fn open(gpa: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map) InternalError!Opened {
    const loop = try gpa.create(dbus.event_loop.EventLoop);
    errdefer gpa.destroy(loop);
    loop.* = dbus.event_loop.EventLoop.init(gpa) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.NoSessionBus,
    };
    errdefer loop.deinit();

    const uid = linux.getuid();
    var resolved = try resolveSessionAddress(gpa, env, uid);
    defer resolved.deinit(gpa);

    const bus = dbus.client.Bus.connectUnix(gpa, loop, io, resolved.path, resolved.abstract, uid) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return error.NoSessionBus;
    };
    errdefer bus.deinit();

    const session_path = openSecretSession(gpa, io, bus, loop) catch |err| switch (err) {
        error.CallFailed => return error.ServiceUnavailable,
        else => |e| return e,
    };

    return .{ .loop = loop, .bus = bus, .session_path = session_path };
}

fn openSecretSession(gpa: std.mem.Allocator, io: std.Io, bus: *dbus.client.Bus, loop: *dbus.event_loop.EventLoop) InternalError![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var w = dbus.Writer.init(gpa, &body, bus.conn.endian);
    try w.string(plain_algorithm);
    try w.beginVariant("s");
    try w.string("");

    const msg = dbus.Message{
        .msg_type = .method_call,
        .serial = 0,
        .path = root_path,
        .interface = service_iface,
        .member = "OpenSession",
        .destination = bus_name,
        .body_signature = "sv",
        .body = body.items,
    };
    var reply = try callAndWait(io, bus, loop, gpa, msg, call_deadline_ms);
    defer reply.deinit(gpa);

    var r = dbus.Reader.init(reply.body, reply.endian);
    const output = r.readValue(gpa, "v") catch |err| return badReplyOr(err);
    dbus.unmarshal.freeValue(gpa, output);
    const path = r.objectPath() catch |err| return badReplyOr(err);
    return gpa.dupe(u8, path);
}

const SearchResult = union(enum) {
    none,
    locked,
    item: []u8,
};

fn searchItem(
    gpa: std.mem.Allocator,
    io: std.Io,
    bus: *dbus.client.Bus,
    loop: *dbus.event_loop.EventLoop,
    name: []const u8,
) InternalError!SearchResult {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var w = dbus.Writer.init(gpa, &body, bus.conn.endian);
    try writeAttributes(&w, name);

    const msg = dbus.Message{
        .msg_type = .method_call,
        .serial = 0,
        .path = root_path,
        .interface = service_iface,
        .member = "SearchItems",
        .destination = bus_name,
        .body_signature = "a{ss}",
        .body = body.items,
    };
    var reply = try callAndWait(io, bus, loop, gpa, msg, call_deadline_ms);
    defer reply.deinit(gpa);

    var r = dbus.Reader.init(reply.body, reply.endian);
    const unlocked = r.readValue(gpa, "ao") catch |err| return badReplyOr(err);
    defer dbus.unmarshal.freeValue(gpa, unlocked);
    const locked = r.readValue(gpa, "ao") catch |err| return badReplyOr(err);
    defer dbus.unmarshal.freeValue(gpa, locked);

    if (unlocked.array.len > 0) return .{ .item = try gpa.dupe(u8, unlocked.array[0].object_path) };
    if (locked.array.len > 0) return .locked;
    return .none;
}

fn writeAttributes(w: *dbus.Writer, name: []const u8) dbus.Writer.Error!void {
    const ctx = try w.beginArray(8);
    try w.beginStruct();
    try w.string("service");
    try w.string(service_name);
    try w.beginStruct();
    try w.string("account");
    try w.string(name);
    w.endArray(ctx);
}

fn getSecret(
    gpa: std.mem.Allocator,
    io: std.Io,
    bus: *dbus.client.Bus,
    loop: *dbus.event_loop.EventLoop,
    item_path: []const u8,
    session_path: []const u8,
) InternalError![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var w = dbus.Writer.init(gpa, &body, bus.conn.endian);
    try w.objectPath(session_path);

    const msg = dbus.Message{
        .msg_type = .method_call,
        .serial = 0,
        .path = item_path,
        .interface = item_iface,
        .member = "GetSecret",
        .destination = bus_name,
        .body_signature = "o",
        .body = body.items,
    };
    var reply = try callAndWait(io, bus, loop, gpa, msg, call_deadline_ms);
    // The reply carries the credential as plain bytes on the wire, so it is wiped before it is freed.
    defer {
        std.crypto.secureZero(u8, reply.body);
        reply.deinit(gpa);
    }

    var r = dbus.Reader.init(reply.body, reply.endian);
    const secret = r.readValue(gpa, "(oayays)") catch |err| return badReplyOr(err);
    defer dbus.unmarshal.freeValue(gpa, secret);
    const parts = secret.@"struct";
    std.debug.assert(parts.len == 4);
    const value = parts[2].array;
    const out = try gpa.alloc(u8, value.len);
    errdefer gpa.free(out);
    for (value, 0..) |*item, i| {
        out[i] = item.byte;
        item.byte = 0;
    }
    return out;
}

const ItemResult = enum { ok, locked };

fn writeSecret(
    w: *dbus.Writer,
    body: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    session_path: []const u8,
    value: []const u8,
) dbus.Writer.Error!void {
    try w.beginStruct();
    try w.objectPath(session_path);
    const params_ctx = try w.beginArray(1);
    w.endArray(params_ctx);
    const value_ctx = try w.beginArray(1);
    try body.appendSlice(gpa, value);
    w.endArray(value_ctx);
    try w.string(content_type);
}

fn createItem(
    gpa: std.mem.Allocator,
    io: std.Io,
    bus: *dbus.client.Bus,
    loop: *dbus.event_loop.EventLoop,
    session_path: []const u8,
    name: []const u8,
    value: []const u8,
) InternalError!ItemResult {
    const label = try std.fmt.allocPrint(gpa, "chock: {s}", .{name});
    defer gpa.free(label);

    var body: std.ArrayList(u8) = .empty;
    defer {
        std.crypto.secureZero(u8, body.items);
        body.deinit(gpa);
    }
    var w = dbus.Writer.init(gpa, &body, bus.conn.endian);

    const props_ctx = try w.beginArray(8);
    try w.beginStruct();
    try w.string(label_property);
    try w.beginVariant("s");
    try w.string(label);
    try w.beginStruct();
    try w.string(attributes_property);
    try w.beginVariant("a{ss}");
    try writeAttributes(&w, name);
    w.endArray(props_ctx);

    try writeSecret(&w, &body, gpa, session_path, value);
    try w.boolean(true);

    const msg = dbus.Message{
        .msg_type = .method_call,
        .serial = 0,
        .path = default_collection_path,
        .interface = collection_iface,
        .member = "CreateItem",
        .destination = bus_name,
        .body_signature = "a{sv}(oayays)b",
        .body = body.items,
    };
    var reply = try callAndWait(io, bus, loop, gpa, msg, call_deadline_ms);
    defer reply.deinit(gpa);

    var r = dbus.Reader.init(reply.body, reply.endian);
    _ = r.objectPath() catch |err| return badReplyOr(err); // the item path, unused
    const prompt_path = r.objectPath() catch |err| return badReplyOr(err);

    return if (std.mem.eql(u8, prompt_path, "/")) .ok else .locked;
}

const PromptWaiter = struct {
    done: bool = false,
    dismissed: bool = true,

    fn onSignal(ctx: ?*anyopaque, bus: *dbus.client.Bus, signal: *const dbus.Message) void {
        _ = bus;
        const self: *PromptWaiter = @ptrCast(@alignCast(ctx.?));
        var r = dbus.Reader.init(signal.body, signal.endian);
        self.dismissed = r.boolean() catch true;
        self.done = true;
    }
};

fn unlockDefault(
    gpa: std.mem.Allocator,
    io: std.Io,
    bus: *dbus.client.Bus,
    loop: *dbus.event_loop.EventLoop,
) InternalError!bool {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var w = dbus.Writer.init(gpa, &body, bus.conn.endian);

    const objects = try w.beginArray(4);
    try w.objectPath(default_collection_path);
    w.endArray(objects);

    var reply = try callAndWait(io, bus, loop, gpa, .{
        .msg_type = .method_call,
        .serial = 0,
        .path = root_path,
        .interface = service_iface,
        .member = "Unlock",
        .destination = bus_name,
        .body_signature = "ao",
        .body = body.items,
    }, call_deadline_ms);
    defer reply.deinit(gpa);

    var r = dbus.Reader.init(reply.body, reply.endian);
    const unlocked = r.readValue(gpa, "ao") catch |err| return badReplyOr(err);
    defer dbus.unmarshal.freeValue(gpa, unlocked);
    const prompt_path = r.objectPath() catch |err| return badReplyOr(err);

    if (std.mem.eql(u8, prompt_path, "/")) return true;

    var waiter = PromptWaiter{};
    bus.addSignalHandler(.{
        .msg_type = .signal,
        .interface = prompt_iface,
        .member = "Completed",
        .path = prompt_path,
    }, PromptWaiter.onSignal, &waiter) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return error.CallFailed;
    };

    var show: std.ArrayList(u8) = .empty;
    defer show.deinit(gpa);
    var sw = dbus.Writer.init(gpa, &show, bus.conn.endian);
    try sw.string("");

    var shown = callAndWait(io, bus, loop, gpa, .{
        .msg_type = .method_call,
        .serial = 0,
        .path = prompt_path,
        .interface = prompt_iface,
        .member = "Prompt",
        .destination = bus_name,
        .body_signature = "s",
        .body = show.items,
    }, call_deadline_ms) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => false,
    };
    shown.deinit(gpa);

    const slice_ms: i32 = 50;
    const deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
        .raw = .fromNanoseconds(unlock_deadline_ms * std.time.ns_per_ms),
        .clock = .awake,
    });
    while (!waiter.done) {
        _ = loop.dispatch(slice_ms);
        if (!std.Io.Clock.Timestamp.now(io, .awake).compare(.lt, deadline)) return false;
    }

    return !waiter.dismissed;
}

fn fault(
    self: *Driver,
    gpa: std.mem.Allocator,
    diag: ?*?store.Diagnostic,
    name: []const u8,
    kind: Fault,
    unreadable: bool,
) store.Error {
    self.last_fault = kind;
    if (store.wantsDiagnostic(diag)) {
        _ = store.note(diag, .{ .secret_service_refused = .{
            .verb = if (unreadable) store.reading_verb else store.storing_verb,
            .name = try gpa.dupe(u8, name),
            .fault = kind,
        } });
    }
    return if (unreadable) error.StoreUnreadable else error.StoreUnwritable;
}

fn mapErr(
    self: *Driver,
    gpa: std.mem.Allocator,
    diag: ?*?store.Diagnostic,
    name: []const u8,
    err: InternalError,
    unreadable: bool,
) store.Error {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    const kind: Fault = switch (err) {
        error.NoSessionBus => .no_session_bus,
        error.ServiceUnavailable => .service_unavailable,
        error.CallFailed, error.ValueTooLong => .call_failed,
        error.CollectionLocked => .collection_locked,
        error.BadReply => .bad_reply,
        error.OutOfMemory => unreachable,
    };
    return fault(self, gpa, diag, name, kind, unreadable);
}

pub const Driver = struct {
    env: *const std.process.Environ.Map,
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

        var opened = open(gpa, io, self.env) catch |err| return mapErr(self, gpa, diag, name, err, true);
        defer opened.deinit(gpa);

        var found = searchItem(gpa, io, opened.bus, opened.loop, name) catch |err| return mapErr(self, gpa, diag, name, err, true);
        if (found == .locked) {
            const opened_now = unlockDefault(gpa, io, opened.bus, opened.loop) catch |err|
                return mapErr(self, gpa, diag, name, err, true);
            if (!opened_now) return fault(self, gpa, diag, name, .collection_locked, true);
            found = searchItem(gpa, io, opened.bus, opened.loop, name) catch |err|
                return mapErr(self, gpa, diag, name, err, true);
        }
        switch (found) {
            .none => return null,
            .locked => return fault(self, gpa, diag, name, .collection_locked, true),
            .item => |item_path| {
                defer gpa.free(item_path);
                const secret = getSecret(gpa, io, opened.bus, opened.loop, item_path, opened.session_path) catch |err|
                    return mapErr(self, gpa, diag, name, err, true);
                return secret;
            },
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

        var opened = open(gpa, io, self.env) catch |err| return mapErr(self, gpa, diag, name, err, false);
        defer opened.deinit(gpa);

        const result = createItem(gpa, io, opened.bus, opened.loop, opened.session_path, name, value) catch |err| {
            if (err != error.CollectionLocked) return mapErr(self, gpa, diag, name, err, false);
            const opened_now = unlockDefault(gpa, io, opened.bus, opened.loop) catch |second|
                return mapErr(self, gpa, diag, name, second, false);
            if (!opened_now) return fault(self, gpa, diag, name, .collection_locked, false);
            const again = createItem(gpa, io, opened.bus, opened.loop, opened.session_path, name, value) catch |second|
                return mapErr(self, gpa, diag, name, second, false);
            return switch (again) {
                .ok => {},
                .locked => fault(self, gpa, diag, name, .collection_locked, false),
            };
        };
        switch (result) {
            .ok => return,
            .locked => {
                const opened_now = unlockDefault(gpa, io, opened.bus, opened.loop) catch |err|
                    return mapErr(self, gpa, diag, name, err, false);
                if (!opened_now) return fault(self, gpa, diag, name, .collection_locked, false);
                const again = createItem(gpa, io, opened.bus, opened.loop, opened.session_path, name, value) catch |err|
                    return mapErr(self, gpa, diag, name, err, false);
                return switch (again) {
                    .ok => {},
                    .locked => fault(self, gpa, diag, name, .collection_locked, false),
                };
            },
        }
    }
};

const testing = std.testing;

test "the advice for each fault is distinct, and the two generic faults carry none" {
    const locked = adviceFor(.collection_locked).?;
    const no_bus = adviceFor(.no_session_bus).?;
    const unavailable = adviceFor(.service_unavailable).?;
    try testing.expect(!std.mem.eql(u8, locked, no_bus));
    try testing.expect(!std.mem.eql(u8, locked, unavailable));
    try testing.expect(std.mem.indexOf(u8, locked, "secret-tool") != null);
    try testing.expect(std.mem.indexOf(u8, locked, "ssh") != null);
    try testing.expectEqual(@as(?[]const u8, null), adviceFor(.call_failed));
    try testing.expectEqual(@as(?[]const u8, null), adviceFor(.bad_reply));
}

test "with no DBUS_SESSION_BUS_ADDRESS, the fallback names this process's own uid" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();

    const uid = linux.getuid();
    var resolved = try resolveSessionAddress(gpa, &env, uid);
    defer resolved.deinit(gpa);

    var expected_buf: [64]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buf, "/run/user/{d}/bus", .{uid});
    try testing.expectEqualStrings(expected, resolved.path);
    try testing.expect(!resolved.abstract);
}

test "DBUS_SESSION_BUS_ADDRESS with a unix path is honoured over the fallback" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/4242/bus");

    var resolved = try resolveSessionAddress(gpa, &env, 1);
    defer resolved.deinit(gpa);

    try testing.expectEqualStrings("/run/user/4242/bus", resolved.path);
    try testing.expect(!resolved.abstract);
}

test "an abstract socket address is honoured, and reported as abstract" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("DBUS_SESSION_BUS_ADDRESS", "unix:abstract=/tmp/dbus-abcdef,guid=deadbeef");

    var resolved = try resolveSessionAddress(gpa, &env, 1);
    defer resolved.deinit(gpa);

    try testing.expectEqualStrings("/tmp/dbus-abcdef", resolved.path);
    try testing.expect(resolved.abstract);
}

test "a malformed DBUS_SESSION_BUS_ADDRESS falls back rather than failing" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("DBUS_SESSION_BUS_ADDRESS", "not-an-address-at-all");

    const uid: linux.uid_t = 7;
    var resolved = try resolveSessionAddress(gpa, &env, uid);
    defer resolved.deinit(gpa);

    try testing.expectEqualStrings("/run/user/7/bus", resolved.path);
}

test "the search attributes carry a service/chock and account/name entry, round tripped" {
    const gpa = testing.allocator;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var w = dbus.Writer.init(gpa, &body, .little);
    try writeAttributes(&w, "work");

    var r = dbus.Reader.init(body.items, .little);
    const v = try r.readValue(gpa, "a{ss}");
    defer dbus.unmarshal.freeValue(gpa, v);

    try testing.expectEqual(@as(usize, 2), v.array.len);
    try testing.expectEqualStrings("service", v.array[0].dict_entry[0].string);
    try testing.expectEqualStrings(service_name, v.array[0].dict_entry[1].string);
    try testing.expectEqualStrings("account", v.array[1].dict_entry[0].string);
    try testing.expectEqualStrings("work", v.array[1].dict_entry[1].string);
}

test "the secret struct embeds the value bytes with no padding drift, round tripped" {
    const gpa = testing.allocator;
    const value = "sk-not-a-real-key";
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var w = dbus.Writer.init(gpa, &body, .little);
    try writeSecret(&w, &body, gpa, "/org/freedesktop/secrets/session/s1", value);

    var r = dbus.Reader.init(body.items, .little);
    const v = try r.readValue(gpa, "(oayays)");
    defer dbus.unmarshal.freeValue(gpa, v);
    const parts = v.@"struct";

    try testing.expectEqualStrings("/org/freedesktop/secrets/session/s1", parts[0].object_path);
    try testing.expectEqual(@as(usize, 0), parts[1].array.len);
    try testing.expectEqual(value.len, parts[2].array.len);
    for (parts[2].array, value) |got, want| try testing.expectEqual(want, got.byte);
    try testing.expectEqualStrings(content_type, parts[3].string);
}

test "a name this driver holds nothing for reads back as nothing, when a session bus answers" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var driver = Driver{ .env = &env };
    const secrets = driver.secrets();

    var diag: ?store.Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    const held = secrets.get(gpa, testing.io, "chock-test-name-no-login-ever-stored", &diag) catch |err| {
        switch (driver.last_fault orelse return err) {
            .no_session_bus, .service_unavailable, .collection_locked => return error.SkipZigTest,
            .call_failed, .bad_reply => return err,
        }
    };
    try testing.expect(held == null);
}

test {
    testing.refAllDecls(@This());
}

test "a locked collection is told from a fault by the error name it is refused with" {
    try testing.expect(isLockedErrorName("org.freedesktop.Secret.Error.IsLocked"));
    try testing.expect(isLockedErrorName("org.freedesktop.DBus.Error.AccessDenied"));

    for ([_][]const u8{
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.NoReply",
        "org.freedesktop.Secret.Error.NoSuchObject",
        "",
    }) |other| {
        try testing.expect(!isLockedErrorName(other));
    }
}

test "the locked fault is the one that carries advice" {
    try testing.expect(adviceFor(.collection_locked) != null);
    try testing.expect(adviceFor(.call_failed) == null);
}
