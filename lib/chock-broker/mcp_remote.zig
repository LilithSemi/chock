//! The socket half of the remote MCP transport. The JSON-RPC and the event
//! stream reading live in `chock-core`, which never holds a credential: this
//! file adds the header, refuses a destination the policy did not name, and
//! pins the address it checked.

const std = @import("std");

const chock_net = @import("chock-net");
const chock_policy = @import("chock-policy");

const actions = @import("actions.zig");
const network = @import("network.zig");

/// Nothing streams for long: a reply is one JSON-RPC message.
const transfer_bytes = 4096;

const head_bytes = 4096;

/// A session asks a server for its tools once and then calls it, so a handful
/// of records covers a turn. Past the bound the oldest are kept.
pub const max_records = 64;

pub const session_header = "Mcp-Session-Id";

pub const version_header = "MCP-Protocol-Version";

/// Both content types a server may answer a request with, in the order the
/// specification writes them.
pub const accept_header = "application/json, text/event-stream";

pub const Error = std.mem.Allocator.Error || error{
    /// The URL names a host the policy did not approve for this server.
    HostNotApproved,
    UrlNotUsable,
    /// A credential never crosses a network in the clear. `mcp.remoteOf`
    /// refuses a plain URL when the file is read, and this refuses the one
    /// thing that would make a plain URL dangerous.
    CredentialNotSendableInTheClear,
    UrlCarriesUserInformation,
    AddressNotPermitted,
    /// An endpoint is configuration, so a redirect reaches nothing.
    Redirected,
    EncodingNotReadable,
    /// A credential that cannot be written into a header without writing a
    /// second one. It is never sent.
    HeaderNotUsable,
    Failed,
};

pub const Kind = enum { json, event_stream, other };

pub const Outcome = enum {
    answered,
    refused_by_policy,
    refused_by_address,
    redirected,
    no_answer,

    pub fn text(self: Outcome) []const u8 {
        return @tagName(self);
    }
};

pub const Record = struct {
    about: []const u8,
    status: u16 = 0,
    outcome: Outcome,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Posted = struct {
    status: u16,
    kind: Kind = .other,
    session_id: []const u8 = "",
    /// Null for an answer with no body, such as the 202 a notification gets.
    live: ?*Live = null,
};

/// One answer being read. The client, the request and the response outlive
/// the call that made them, so a reply that arrives in pieces still arrives.
pub const Live = struct {
    gpa: std.mem.Allocator,
    client: std.http.Client,
    request: std.http.Client.Request,
    response: std.http.Client.Response,
    reader: *std.Io.Reader,
    transfer: [transfer_bytes]u8 = undefined,
    /// Held here and not on a stack: the answer is read after the call that
    /// made it has returned.
    head: [head_bytes]u8 = undefined,
    ended: bool = false,

    pub const ReadError = error{ Late, Gone };

    pub fn read(
        self: *Live,
        io: std.Io,
        into: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReadError!usize {
        if (self.ended) return 0;
        if (std.Io.Clock.Timestamp.now(io, .awake).compare(.gte, deadline)) return error.Late;

        const count = try readBefore(self.reader, io, into, deadline);
        if (count == 0) self.ended = true;
        return count;
    }

    pub fn close(self: *Live) void {
        self.request.deinit();
        self.client.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }
};

fn readBefore(
    reader: *std.Io.Reader,
    io: std.Io,
    into: []u8,
    deadline: std.Io.Clock.Timestamp,
) Live.ReadError!usize {
    const Race = union(enum) {
        read: error{Gone}!usize,
        deadline: std.Io.Cancelable!void,
    };
    var completed: [2]Race = undefined;
    var race: std.Io.Select(Race) = .init(io, &completed);
    defer race.cancelDiscard();
    race.async(.read, readOne, .{ reader, into });
    race.async(.deadline, waitUntil, .{ deadline, io });

    return switch (race.await() catch return error.Gone) {
        .read => |result| result catch return error.Gone,
        .deadline => |result| {
            result catch return error.Gone;
            return error.Late;
        },
    };
}

fn readOne(reader: *std.Io.Reader, into: []u8) error{Gone}!usize {
    return reader.readSliceShort(into) catch error.Gone;
}

fn waitUntil(deadline: std.Io.Clock.Timestamp, io: std.Io) std.Io.Cancelable!void {
    return deadline.wait(io);
}

pub const Session = struct {
    gpa: std.mem.Allocator,

    /// The server this reaches, as the project named it.
    server: []const u8,

    /// The one host the policy approved. A URL naming another is refused.
    host: []const u8,

    url: []const u8,

    port: u16,

    /// Null when no credential reached this server.
    header: ?Header = null,

    resolver: actions.Resolver = .system,

    /// The address check lives only in `network.zig`: two copies of a
    /// security check would drift apart.
    reachable: *const fn (address: actions.Resolver.Address) bool = network.addressIsReachable,

    records: [max_records]Record = undefined,
    kept: usize = 0,

    pub fn post(
        self: *Session,
        arena: std.mem.Allocator,
        io: std.Io,
        body: []const u8,
        session_id: []const u8,
        protocol_version: []const u8,
    ) Error!Posted {
        const uri = std.Uri.parse(self.url) catch return error.UrlNotUsable;
        const secure = std.mem.eql(u8, uri.scheme, "https");
        if (!secure and !std.mem.eql(u8, uri.scheme, "http")) return error.UrlNotUsable;
        if (!secure and self.header != null) return error.CredentialNotSendableInTheClear;
        // `std.http.Client` turns `user:secret@host` into an Authorization header.
        if (uri.user != null or uri.password != null) return error.UrlCarriesUserInformation;

        const named = uri.host orelse return error.UrlNotUsable;
        const host = try named.toRawMaybeAlloc(arena);
        if (!std.mem.eql(u8, host, self.host)) return error.HostNotApproved;

        // The rule lives in chock-policy, which is also what reads the block
        // that names the header, so there is one rule and not two.
        if (self.header) |one| {
            if (!chock_policy.secrets.headerIsWellFormed(one.name)) return error.HeaderNotUsable;
            if (!chock_policy.secrets.headerValueIsSendable(one.value)) return error.HeaderNotUsable;
        }

        var addresses: [actions.Resolver.max_addresses]actions.Resolver.Address = undefined;
        const found = self.resolver.lookup(io, host, &addresses) catch |err| return switch (err) {
            // Addresses past the bound stay unchecked, where a hostile zone hides the loopback.
            error.TooManyAddresses => error.AddressNotPermitted,
            error.NotResolved => error.Failed,
        };
        for (addresses[0..found]) |address| {
            if (!self.reachable(address)) return error.AddressNotPermitted;
        }

        const live = try self.gpa.create(Live);
        var kept = false;
        defer if (!kept) self.gpa.destroy(live);

        live.* = .{
            .gpa = self.gpa,
            .client = .{ .allocator = self.gpa, .io = io },
            .request = undefined,
            .response = undefined,
            .reader = undefined,
        };
        var client_open = true;
        defer if (!kept and client_open) live.client.deinit();

        const protocol = std.http.Client.Protocol.fromUri(uri) orelse return error.UrlNotUsable;
        const pinned = actions.pinnedConnection(
            self.gpa,
            io,
            &live.client,
            host,
            addresses[0..found],
            self.port,
            protocol,
        ) catch return error.Failed;

        var headers: std.ArrayList(std.http.Header) = .empty;
        try headers.append(arena, .{ .name = "Accept", .value = accept_header });
        if (session_id.len != 0) {
            try headers.append(arena, .{ .name = session_header, .value = session_id });
        }
        if (protocol_version.len != 0) {
            try headers.append(arena, .{ .name = version_header, .value = protocol_version });
        }
        if (self.header) |one| {
            try headers.append(arena, .{ .name = one.name, .value = one.value });
        }

        live.request = live.client.request(.POST, uri, .{
            .keep_alive = false,
            // A 3xx is refused below, so nothing follows a Location.
            .redirect_behavior = .unhandled,
            .connection = pinned,
            .extra_headers = try headers.toOwnedSlice(arena),
            .headers = .{
                .user_agent = .{ .override = actions.user_agent },
                .content_type = .{ .override = "application/json" },
                .accept_encoding = .{ .override = "identity" },
                // URL user information is refused above, and never travels.
                .authorization = .omit,
            },
        }) catch {
            // `Client.deinit` asserts no connection is out, and a failed
            // request has no `deinit` to give one back.
            if (pinned) |connection| live.client.connection_pool.release(connection, io);
            return error.Failed;
        };
        var request_open = true;
        defer if (!kept and request_open) live.request.deinit();

        // A compressed answer would need a decompressor to outlive this call,
        // and a JSON-RPC message is small, so identity costs nothing. The
        // array makes an answer that ignores the header an error and not bytes
        // read as if they were the reply.
        live.request.accept_encoding = identity_only;

        const writable = try arena.dupe(u8, body);
        live.request.sendBodyComplete(writable) catch return error.Failed;

        live.response = live.request.receiveHead(&live.head) catch |err| switch (err) {
            error.HttpContentEncodingUnsupported => return error.EncodingNotReadable,
            else => return error.Failed,
        };

        const status = @backingInt(live.response.head.status);
        if (status >= 300 and status < 400) return error.Redirected;

        // Read before the reader is taken: it writes over the head's strings.
        const kind = kindOf(live.response.head.content_type);
        const named_session = try sessionIdIn(arena, live.response.head);

        if (live.response.head.content_length) |length| {
            if (length == 0) {
                // A 202 for a notification, with nothing to read.
                return .{ .status = status, .kind = kind, .session_id = named_session };
            }
        }

        live.reader = live.response.reader(&live.transfer);
        kept = true;
        client_open = false;
        request_open = false;
        return .{
            .status = status,
            .kind = kind,
            .session_id = named_session,
            .live = live,
        };
    }

    /// Kept until a log lock arrives, the way a used secret is.
    pub fn note(self: *Session, about: []const u8, status: u16, outcome: Outcome) void {
        if (self.kept == max_records) return;
        self.records[self.kept] = .{ .about = about, .status = status, .outcome = outcome };
        self.kept += 1;
    }

    pub fn taken(self: *Session) []const Record {
        const out = self.records[0..self.kept];
        return out;
    }

    pub fn forget(self: *Session) void {
        self.kept = 0;
    }
};

const identity_only = blk: {
    const count = @typeInfo(std.http.ContentEncoding).@"enum".field_names.len;
    var result: [count]bool = @splat(false);
    result[@backingInt(std.http.ContentEncoding.identity)] = true;
    break :blk result;
};

pub fn kindOf(content_type: ?[]const u8) Kind {
    const named = content_type orelse return .other;
    // A type carries parameters, such as `; charset=utf-8`.
    const base = std.mem.trim(u8, firstOf(named), " \t");
    if (std.ascii.eqlIgnoreCase(base, "application/json")) return .json;
    if (std.ascii.eqlIgnoreCase(base, "text/event-stream")) return .event_stream;
    return .other;
}

fn firstOf(value: []const u8) []const u8 {
    const semicolon = std.mem.indexOfScalar(u8, value, ';') orelse return value;
    return value[0..semicolon];
}

pub fn sessionIdIn(
    arena: std.mem.Allocator,
    head: std.http.Client.Response.Head,
) std.mem.Allocator.Error![]const u8 {
    var headers = head.iterateHeaders();
    while (headers.next()) |one| {
        if (!std.ascii.eqlIgnoreCase(one.name, session_header)) continue;
        const value = std.mem.trim(u8, one.value, " \t");
        if (!isVisibleAscii(value)) return "";
        return arena.dupe(u8, value);
    }
    return "";
}

/// The specification holds a session id to visible ASCII, which is also what
/// keeps it out of a header it was never meant to reach.
fn isVisibleAscii(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte < 0x21 or byte > 0x7e) return false;
    }
    return true;
}

const testing = std.testing;

const SlowReader = struct {
    io: std.Io,
    reader: std.Io.Reader = undefined,
    buffer: [1]u8 = undefined,

    fn init(self: *SlowReader) void {
        self.reader = .{
            .vtable = &.{ .stream = stream },
            .buffer = &self.buffer,
            .seek = 0,
            .end = 0,
        };
    }

    fn stream(
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        _ = writer;
        _ = limit;
        const self: *SlowReader = @fieldParentPtr("reader", reader);
        std.Io.sleep(self.io, .fromSeconds(1), .awake) catch return error.ReadFailed;
        return error.EndOfStream;
    }
};

test "an HTTP body read is interrupted at its deadline" {
    const io = testing.io;
    var slow = SlowReader{ .io = io };
    slow.init();
    var into: [1]u8 = undefined;
    const deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
        .raw = .fromMilliseconds(5),
        .clock = .awake,
    });
    try testing.expectError(error.Late, readBefore(&slow.reader, io, &into, deadline));
}

test "an HTTP body read that answers before its deadline wins the race" {
    const io = testing.io;
    var source = std.Io.Reader.fixed("answer");
    var into: [6]u8 = undefined;
    const deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    const count = try readBefore(&source, io, &into, deadline);
    try testing.expectEqual(@as(usize, 6), count);
    try testing.expectEqualStrings("answer", into[0..count]);
}

const StubResolver = struct {
    answers: []const actions.Resolver.Address,
    asked: usize = 0,
    fail: ?actions.Resolver.LookupError = null,

    fn resolver(self: *StubResolver) actions.Resolver {
        return .{ .ptr = self, .vtable = &stub_vtable };
    }

    fn lookupFn(
        ptr: *anyopaque,
        io: std.Io,
        host: []const u8,
        into: []actions.Resolver.Address,
    ) actions.Resolver.LookupError!usize {
        _ = io;
        _ = host;
        const self: *StubResolver = @ptrCast(@alignCast(ptr));
        self.asked += 1;
        if (self.fail) |err| return err;
        const count = @min(into.len, self.answers.len);
        @memcpy(into[0..count], self.answers[0..count]);
        return count;
    }
};

const stub_vtable = actions.Resolver.VTable{ .lookup = StubResolver.lookupFn };

fn ip4(a: u8, b: u8, c: u8, d: u8) actions.Resolver.Address {
    return .{ .ip4 = .{ .bytes = .{ a, b, c, d }, .port = 443 } };
}

test "a URL naming a host the policy did not approve is refused before anything resolves" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var stub = StubResolver{ .answers = &.{ip4(93, 184, 216, 34)} };
    var session = Session{
        .gpa = testing.allocator,
        .server = "probe",
        .host = "mcp.example.com",
        .url = "https://elsewhere.example.com/mcp",
        .port = 443,
        .resolver = stub.resolver(),
    };

    try testing.expectError(
        error.HostNotApproved,
        session.post(arena_state.allocator(), testing.io, "{}", "", ""),
    );
    try testing.expectEqual(@as(usize, 0), stub.asked);
}

test "an address on this machine is refused by the one shared check" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    // The real check, not a copy of it: loopback and the metadata address are
    // refused whatever a policy says about the name.
    try testing.expect(!network.addressIsReachable(ip4(127, 0, 0, 1)));
    try testing.expect(!network.addressIsReachable(ip4(169, 254, 169, 254)));

    var stub = StubResolver{ .answers = &.{ ip4(93, 184, 216, 34), ip4(127, 0, 0, 1) } };
    var session = Session{
        .gpa = testing.allocator,
        .server = "probe",
        .host = "mcp.example.com",
        .url = "https://mcp.example.com/mcp",
        .port = 443,
        .resolver = stub.resolver(),
    };

    try testing.expectError(
        error.AddressNotPermitted,
        session.post(arena_state.allocator(), testing.io, "{}", "", ""),
    );
    try testing.expectEqual(@as(usize, 1), stub.asked);
}

test "more addresses than this checks is a refusal, and never the ones it did check" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var stub = StubResolver{ .answers = &.{}, .fail = error.TooManyAddresses };
    var session = Session{
        .gpa = testing.allocator,
        .server = "probe",
        .host = "mcp.example.com",
        .url = "https://mcp.example.com/mcp",
        .port = 443,
        .resolver = stub.resolver(),
    };

    try testing.expectError(
        error.AddressNotPermitted,
        session.post(arena_state.allocator(), testing.io, "{}", "", ""),
    );
}

test "a url this transport will not carry is refused by its own reason" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var stub = StubResolver{ .answers = &.{ip4(93, 184, 216, 34)} };

    const cases = [_]struct { url: []const u8, want: anyerror }{
        .{ .url = "ftp://mcp.example.com/mcp", .want = error.UrlNotUsable },
        .{ .url = "https://user:secret@mcp.example.com/mcp", .want = error.UrlCarriesUserInformation },
        .{ .url = "not a url at all", .want = error.UrlNotUsable },
        .{ .url = "https:///mcp", .want = error.UrlNotUsable },
    };

    for (cases) |one| {
        var session = Session{
            .gpa = testing.allocator,
            .server = "probe",
            .host = "mcp.example.com",
            .url = one.url,
            .port = 443,
            .resolver = stub.resolver(),
        };
        try testing.expectError(one.want, session.post(arena, testing.io, "{}", "", ""));
    }
}

test "a content type says which of the two shapes a reply took" {
    try testing.expectEqual(Kind.json, kindOf("application/json"));
    try testing.expectEqual(Kind.json, kindOf("application/json; charset=utf-8"));
    try testing.expectEqual(Kind.event_stream, kindOf("text/event-stream"));
    try testing.expectEqual(Kind.event_stream, kindOf("TEXT/EVENT-STREAM"));
    try testing.expectEqual(Kind.other, kindOf("text/html"));
    try testing.expectEqual(Kind.other, kindOf(null));
}

test "a header a credential cannot be written into is refused before a request is made" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var stub = StubResolver{ .answers = &.{ip4(93, 184, 216, 34)} };
    var session = Session{
        .gpa = testing.allocator,
        .server = "probe",
        .host = "mcp.example.com",
        .url = "https://mcp.example.com/mcp",
        .port = 443,
        .resolver = stub.resolver(),
        .header = .{ .name = "Authorization", .value = "Bearer a\r\nX-Other: b" },
    };

    try testing.expectError(
        error.HeaderNotUsable,
        session.post(arena_state.allocator(), testing.io, "{}", "", ""),
    );
    try testing.expectEqual(@as(usize, 0), stub.asked);

    // The rule is chock-policy's own, so one name rule serves the block that
    // writes a header and the request that sends it.
    try testing.expect(chock_policy.secrets.headerIsWellFormed("X-Api-Key"));
    try testing.expect(!chock_policy.secrets.headerValueIsSendable("a\r\nb"));
}

test "a record is kept for the log, and the bound holds" {
    var session = Session{
        .gpa = testing.allocator,
        .server = "probe",
        .host = "mcp.example.com",
        .url = "https://mcp.example.com/mcp",
        .port = 443,
    };

    session.note("discover", 200, .answered);
    session.note("echo", 0, .refused_by_address);
    try testing.expectEqual(@as(usize, 2), session.taken().len);
    try testing.expectEqualStrings("discover", session.taken()[0].about);
    try testing.expectEqualStrings("refused_by_address", session.taken()[1].outcome.text());

    session.forget();
    try testing.expectEqual(@as(usize, 0), session.taken().len);

    for (0..max_records + 8) |_| session.note("echo", 200, .answered);
    try testing.expectEqual(max_records, session.taken().len);
}

comptime {
    // `chock_net` is imported for the address type the resolver answers with,
    // which `network.zig` owns.
    _ = chock_net;
}

test "a credential never crosses a network in the clear" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var stub = StubResolver{ .answers = &.{ip4(93, 184, 216, 34)} };
    var session = Session{
        .gpa = testing.allocator,
        .server = "probe",
        .host = "mcp.example.com",
        .url = "http://mcp.example.com/mcp",
        .port = 80,
        .resolver = stub.resolver(),
        .header = .{ .name = "Authorization", .value = "Bearer secret" },
    };

    try testing.expectError(
        error.CredentialNotSendableInTheClear,
        session.post(arena_state.allocator(), testing.io, "{}", "", ""),
    );
    try testing.expectEqual(@as(usize, 0), stub.asked);
}
