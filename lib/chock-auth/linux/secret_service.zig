//! A second Linux credential driver: the freedesktop secret service,
//! reached over the D-Bus session bus, instead of the file in
//! `linux/secrets.zig`. Which one a build uses is a choice made above this
//! file; this file never makes that choice itself.
//!
//! ## Nothing here waits without a bound
//!
//! The Darwin Keychain driver was rewritten because the command it used to
//! run could hang on an authorisation dialog nobody was there to answer.
//! The same shape of bug is possible here, so every D-Bus call this file
//! makes goes through `callAndWait`, which dispatches the event loop in
//! bounded slices and gives up once `call_deadline_ms` passes. Chock's
//! session `Io` cannot start a thread to watch a call that never returns,
//! so the bound has to be the whole answer.
//!
//! ## Why "plain"
//!
//! `Service.OpenSession` offers two algorithms. `"plain"` sends the
//! credential unencrypted over the session bus, a local, kernel mediated
//! socket, and needs no cryptography here. The other,
//! `dh-ietf1024-sha256-aes128-cbc-pkcs7`, would mean implementing
//! Diffie-Hellman and AES-CBC in this file, so it is not offered.
//!
//! ## The failure that matters
//!
//! Tried against a real gnome-keyring on a session with no desktop: the
//! session bus exists, the service activates, and `OpenSession` succeeds.
//! Every cheap check passes. Then the default collection turns out to be
//! locked, and unlocking it means a prompt nobody here can answer.
//!
//! So this driver never calls `Unlock` and never calls `Prompt`. A locked
//! collection is reported as its own fault, with advice that says a
//! desktop login or `secret-tool unlock` is what opens it, and that a
//! machine reached only over ssh usually cannot do either.
//!
//! ## No fallback
//!
//! Selection between this driver and the file one is configured, and this
//! file does not choose. Falling back to the file driver on a locked
//! collection would put a credential somewhere the user did not ask for,
//! which is the one thing ruled out here.

const std = @import("std");
const dbus = @import("dbus");
const store = @import("../store.zig");

const linux = std.os.linux;

/// The bound every D-Bus call in this file waits under. See `callAndWait`.
pub const call_deadline_ms: i64 = 5000;

/// The value stored under the `"service"` attribute on every item this
/// driver writes, the way the Darwin driver names `service_name`.
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

/// What went wrong reaching the secret service. `store.Diagnostic` has no
/// variant of its own for this driver yet: see `Driver.last_fault`.
const faults = @import("secret_fault.zig");

pub const Fault = faults.Fault;
pub const adviceFor = faults.adviceFor;

const InternalError = error{
    NoSessionBus,
    ServiceUnavailable,
    CallFailed,
    BadReply,
    ValueTooLong,
} || std.mem.Allocator.Error;

/// Turn an unmarshalling fault into `BadReply`, keeping `OutOfMemory` as
/// itself. Every reply this file reads goes through this on its way out.
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

/// Where the session bus is. `DBUS_SESSION_BUS_ADDRESS` names it on every
/// desktop session; the `dbus` library does not read it, so this file
/// does. Caller owns the result.
fn resolveSessionAddress(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    uid: linux.uid_t,
) std.mem.Allocator.Error!Resolved {
    if (env.get("DBUS_SESSION_BUS_ADDRESS")) |value| {
        if (try parseFirstUnix(gpa, value)) |resolved| return resolved;
    }
    // Only reached when the variable is missing or unusable: the
    // conventional location every desktop session's variable points at.
    return .{ .path = try std.fmt.allocPrint(gpa, "/run/user/{d}/bus", .{uid}), .abstract = false };
}

/// The first `unix:` address in `value`, or null when there is none. An
/// address this driver cannot parse falls back rather than fails: see
/// `resolveSessionAddress`.
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

/// Captures a method reply. Only ever holds an owned copy of the body: the
/// message the callback receives is invalid the moment it returns.
const Waiter = struct {
    gpa: std.mem.Allocator,
    done: bool = false,
    disconnected: bool = false,
    is_return: bool = false,
    oom: bool = false,
    body: []u8 = &.{},
    signature: []u8 = &.{},
    endian: std.builtin.Endian = .little,

    fn onReply(ctx: ?*anyopaque, conn: *dbus.connection.Connection, reply: ?*const dbus.Message) void {
        _ = conn;
        const self: *Waiter = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse {
            self.disconnected = true;
            return;
        };
        self.is_return = r.msg_type == .method_return;
        if (!self.is_return) return;
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

/// Send `msg` and wait for its reply, never longer than `deadline_ms`.
///
/// This is the only wait in this file, and every call goes through it.
/// A wait with no bound is the fault the Darwin driver was rewritten to
/// remove, and it must not come back on this platform.
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

    // **The deadline is read off a clock and never counted in slices.**
    // `dispatch` returns as soon as any descriptor is ready, so on a busy bus
    // it returns at once and a slice count would run out in no time at all.
    // `.awake` and not `.real`, so the deadline does not move when NTP steps
    // the clock.
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
    if (waiter.disconnected or !waiter.is_return) return error.CallFailed;
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

/// Connect to the session bus and open a `"plain"` secret service session.
/// The event loop is heap allocated: `Bus.connectUnix` keeps a pointer to
/// it, so its address must not move once that call is made.
fn open(gpa: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map) InternalError!Opened {
    const loop = try gpa.create(dbus.event_loop.EventLoop);
    errdefer gpa.destroy(loop);
    // Any epoll fault means there is no reachable bus, whichever one it was,
    // so this does not enumerate them: the library may add another.
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

    // No unlocked path and no locked path is the ordinary first run: see
    // the file's own top comment for the locked case.
    if (unlocked.array.len > 0) return .{ .item = try gpa.dupe(u8, unlocked.array[0].object_path) };
    if (locked.array.len > 0) return .locked;
    return .none;
}

/// The attributes an item is found and stored by: this driver's own
/// service name, paired with the instance name the caller asked for.
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
    // The reply carries the credential as plain bytes on the wire, so it
    // is wiped before it is freed.
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

/// Marshal the Secret struct `(oayays)`: the session, empty parameters,
/// the value, and the content type. `w` and `body` are the same buffer;
/// the value is appended to `body` directly because a byte array's
/// elements need no padding between them.
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
    // The value goes straight into this buffer: wiped before it is freed,
    // the same as every other copy of a credential in this file.
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

    // A prompt other than "/" means the service wants a person to answer
    // it. Nobody here can, so this is the locked case, and not a call to
    // Prompt: see the file's own top comment.
    return if (std.mem.eql(u8, prompt_path, "/")) .ok else .locked;
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
        error.BadReply => .bad_reply,
        error.OutOfMemory => unreachable,
    };
    return fault(self, gpa, diag, name, kind, unreadable);
}

/// The driver.
pub const Driver = struct {
    /// Where `DBUS_SESSION_BUS_ADDRESS` is read from. Nothing in the
    /// `dbus` library reads the process environment, and this driver has
    /// no access of its own, so the caller supplies it, the way
    /// `paths.zig` does.
    env: *const std.process.Environ.Map,
    /// Why the last `get` or `put` failed. `store.Diagnostic` has no
    /// variant of its own for this driver yet, so this is read directly.
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

        const found = searchItem(gpa, io, opened.bus, opened.loop, name) catch |err| return mapErr(self, gpa, diag, name, err, true);
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

        const result = createItem(gpa, io, opened.bus, opened.loop, opened.session_path, name, value) catch |err|
            return mapErr(self, gpa, diag, name, err, false);
        switch (result) {
            .ok => return,
            .locked => return fault(self, gpa, diag, name, .collection_locked, false),
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
    // The host's own environment is not reachable from a test, so this
    // driver gets an empty one and relies on the fallback path. A machine
    // with no session bus, or one whose default collection is locked, has
    // nothing this test can prove: see the file's own top comment for why
    // a locked collection is not this driver's failure to fix.
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
